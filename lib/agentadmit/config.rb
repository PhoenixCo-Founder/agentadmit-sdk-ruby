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

    def initialize
      @app_id = ENV.fetch("AGENTADMIT_APP_ID", "")
      @api_key = ENV.fetch("AGENTADMIT_API_KEY", "")
      self.verify_url = ENV.fetch("AGENTADMIT_VERIFY_URL", "https://api.agentadmit.com/api/v1/verify")
      self.api_url    = ENV.fetch("AGENTADMIT_API_URL", "https://api.agentadmit.com")
      @token_prefix_access = "ag_at_"
      @token_prefix_connection = "ag_ct_"
      # Webhook signing secret (whsec_...) -- shown once when you configure the
      # alert webhook URL in the dashboard. Used by AgentAdmit::Webhook.
      @webhook_secret = ENV.fetch("AGENTADMIT_WEBHOOK_SECRET", "")
      # Max retries on HTTP 429 before raising RateLimitError. Default: 3.
      @max_retries = ENV.fetch("AGENTADMIT_MAX_RETRIES", "3").to_i
    end

    def verify_url=(url)
      validate_url!(url, :verify_url)
      @verify_url = url
    end

    def api_url=(url)
      validate_url!(url, :api_url)
      @api_url = url
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
