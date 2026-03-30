# frozen_string_literal: true

require_relative "agentadmit/version"
require_relative "agentadmit/config"
require_relative "agentadmit/introspection_client"
require_relative "agentadmit/middleware"
require_relative "agentadmit/scope_enforcement"
require_relative "agentadmit/railtie" if defined?(Rails)

module AgentAdmit
  class Error < StandardError; end
  class InvalidTokenError < Error; end
  class InsufficientScopeError < Error; end
  class IntrospectionError < Error; end

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
