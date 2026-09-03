# frozen_string_literal: true

# IMPORTANT: AgentAdmit uses MANDATORY hosted introspection.
# All token validation goes through api.agentadmit.com.
# There is no self-hosted mode. No local JWT validation. No bypass.
# This is required for security, audit logging, and scope enforcement.

require "uri"

module AgentAdmit
  class Config
    attr_accessor :app_id, :api_key, :token_prefix_access, :token_prefix_connection,
                  :webhook_secret, :max_retries

    attr_reader :verify_url, :api_url

    # One hosted-service origin, not two.
    DEFAULT_API_URL    = "https://api.agentadmit.com"
    DEFAULT_VERIFY_URL = "#{DEFAULT_API_URL}/api/v1/verify"
    # Path appended to a non-default api_url to derive the verify URL.
    VERIFY_PATH = "/api/v1/verify"

    def initialize
      @app_id = ENV.fetch("AGENTADMIT_APP_ID", "")
      @api_key = ENV.fetch("AGENTADMIT_API_KEY", "")
      env_verify = ENV["AGENTADMIT_VERIFY_URL"]
      self.verify_url = env_verify.nil? || env_verify.empty? ? DEFAULT_VERIFY_URL : env_verify
      # An AGENTADMIT_VERIFY_URL left unset is not an explicit choice -- it
      # must still follow a non-default api_url (see #api_url=).
      @verify_url_explicit = !(env_verify.nil? || env_verify.empty?)
      self.api_url = ENV.fetch("AGENTADMIT_API_URL", DEFAULT_API_URL)
      @token_prefix_access = "ag_at_"
      @token_prefix_connection = "ag_ct_"
      # Webhook signing secret (whsec_...) -- shown once when you configure the
      # alert webhook URL in the dashboard. Used by AgentAdmit::Webhook.
      @webhook_secret = ENV.fetch("AGENTADMIT_WEBHOOK_SECRET", "")
      # Max retries on HTTP 429 before raising RateLimitError. Default: 3.
      @max_retries = ENV.fetch("AGENTADMIT_MAX_RETRIES", "3").to_i
    end

    ##
    # Set the /verify endpoint explicitly. An explicit verify URL always
    # wins -- assigning it pins the endpoint, and a later api_url no longer
    # derives over it.
    #
    def verify_url=(url)
      validate_url!(url, :verify_url)
      @verify_url = url
      @verify_url_explicit = true
    end

    ##
    # Set the hosted API origin. When the verify URL was never chosen
    # explicitly, it FOLLOWS a non-default api_url.
    #
    # One hosted-service origin, not two: an operator who points api_url at a
    # staging service or a local rig and leaves the verify URL alone expects
    # verify to follow. Without this, the scope catalog and token operations
    # go to one service while every per-call verify silently goes to
    # production -- exactly the split caught on the TrainerTracer dogfood rig
    # (Sep 3, 2026).
    #
    def api_url=(url)
      validate_url!(url, :api_url)
      @api_url = url

      return if @verify_url_explicit
      return if url.nil? || url.empty?

      origin = url.sub(%r{/\z}, "")
      return if origin == DEFAULT_API_URL.sub(%r{/\z}, "")

      derived = "#{origin}#{VERIFY_PATH}"
      validate_url!(derived, :verify_url)
      @verify_url = derived
    end

    ##
    # Validate the API key prefix (aa_test_/aa_live_) without ever echoing
    # the key itself.
    #
    # @raise [ConfigurationError] if a non-empty key has the wrong prefix
    #
    def validate_api_key!
      return if api_key.nil? || api_key.empty?
      return if api_key.start_with?("aa_test_", "aa_live_")

      raise ConfigurationError, "api_key must start with 'aa_test_' or 'aa_live_'"
    end

    private

    # Local loopback hostnames / addresses that are allowed over plain HTTP.
    LOCALHOST_HOSTS = %w[localhost 127.0.0.1 [::1]].freeze

    ##
    # Raise ConfigurationError for non-https URLs unless the host is localhost.
    #
    def validate_url!(url, field)
      return if url.nil? || url.empty?

      uri = URI.parse(url)
      return if uri.scheme == "https"

      if uri.scheme == "http" && LOCALHOST_HOSTS.include?(uri.host)
        return
      end

      raise ConfigurationError,
        "#{field} must use https (got: #{url.inspect}). " \
        "Plain http is only permitted for localhost / 127.0.0.1 / [::1]."
    rescue URI::InvalidURIError
      raise ConfigurationError, "#{field} is not a valid URL: #{url.inspect}"
    end
  end
end
