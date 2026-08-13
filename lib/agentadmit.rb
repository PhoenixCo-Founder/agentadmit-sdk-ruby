# frozen_string_literal: true

require_relative "agentadmit/version"

module AgentAdmit
  class Error < StandardError; end

  ##
  # Raised when token validation fails. {#code} carries the machine-readable
  # reason from the API — one of VERIFY_ERROR_CODES (e.g. token_expired,
  # connection_expired, environment_mismatch); unknown codes pass through.
  #
  class InvalidTokenError < Error
    # @return [String] machine-readable error code
    attr_reader :code

    def initialize(message = "Invalid access token", code: "invalid_token")
      super(message)
      @code = code
    end
  end

  class InsufficientScopeError < Error; end
  class IntrospectionError < Error; end
  class ConfigurationError < Error; end

  ##
  # Raised when an inbound alert webhook fails X-AgentAdmit-Signature
  # verification.
  #
  class WebhookSignatureError < Error; end

  ##
  # Error codes /api/v1/verify returns with HTTP 200 and active: false
  # (insufficient_scope arrives with active: true — token valid, scope not
  # granted).
  #
  VERIFY_ERROR_CODES = %w[
    invalid_token
    token_expired
    token_revoked
    connection_revoked
    connection_expired
    environment_mismatch
    insufficient_scope
  ].freeze

  ##
  # Raised when the AgentAdmit introspection endpoint returns HTTP 429 and
  # all retry attempts (with exponential backoff + jitter) have been exhausted.
  #
  # @example
  #   begin
  #     client.verify(token)
  #   rescue AgentAdmit::RateLimitError => e
  #     render json: { error: 'rate_limited', retry_after: e.retry_after }, status: 429
  #   end
  #
  class RateLimitError < Error
    # @return [Float, nil] Seconds to wait before retrying (Retry-After header), or nil.
    attr_reader :retry_after
    # @return [Integer, nil] X-RateLimit-Limit value, or nil.
    attr_reader :limit
    # @return [Integer, nil] X-RateLimit-Remaining value, or nil.
    attr_reader :remaining
    # @return [Integer, nil] X-RateLimit-Reset Unix timestamp, or nil.
    attr_reader :reset

    def initialize(message = "AgentAdmit rate limit exceeded. Max retries exhausted.",
                   retry_after: nil, limit: nil, remaining: nil, reset: nil)
      super(message)
      @retry_after = retry_after
      @limit       = limit
      @remaining   = remaining
      @reset       = reset
    end
  end

  class << self
    attr_accessor :configuration

    def configure
      self.configuration ||= Config.new
      yield(configuration) if block_given?
    end
  end
end

require_relative "agentadmit/config"
require_relative "agentadmit/introspection_client"
require_relative "agentadmit/app_attested_presence"
require_relative "agentadmit/tokens_client"
require_relative "agentadmit/alerts_client"
require_relative "agentadmit/webhook"
require_relative "agentadmit/middleware"
require_relative "agentadmit/caller_consent"
# ScopeEnforcement is an ActiveSupport::Concern — only loadable inside Rails.
require_relative "agentadmit/scope_enforcement" if defined?(ActiveSupport)
require_relative "agentadmit/railtie" if defined?(Rails)
