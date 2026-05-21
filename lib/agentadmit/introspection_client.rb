# frozen_string_literal: true

require "net/http"
require "json"
require "uri"

module AgentAdmit
  ##
  # Mandatory introspection client — validates tokens via AgentAdmit hosted service.
  # No local JWT decode. Every verification call goes through AgentAdmit.
  #
  class IntrospectionClient
    IntrospectionResult = Struct.new(:user_id, :connection_id, :scopes, :agent_label, keyword_init: true) do
      def has_scope?(scope)
        scopes.include?(scope)
      end
    end

    def initialize(config = nil)
      @config = config || AgentAdmit.configuration || Config.new
    end

    ##
    # Validate an ag_at_ token via introspection.
    #
    # Automatically retries on HTTP 429 with exponential backoff + jitter.
    # Raises {RateLimitError} when retries are exhausted.
    #
    # @param token [String] The full token including ag_at_ prefix
    # @return [IntrospectionResult]
    # @raise [InvalidTokenError] if validation fails
    # @raise [IntrospectionError] if the service is unreachable
    # @raise [RateLimitError] if rate-limited and retries exhausted
    #
    def verify(token)
      unless token.start_with?(@config.token_prefix_access)
        raise InvalidTokenError, "Not an AgentAdmit access token"
      end

      max_retries = @config.respond_to?(:max_retries) ? @config.max_retries.to_i : 3
      delay_ms    = 1000 # initial backoff in milliseconds

      uri  = URI.parse(@config.verify_url)
      http = build_http(uri)

      (0..max_retries).each do |attempt|
        request = build_request(uri, token)

        begin
          response = http.request(request)
        rescue StandardError => e
          raise IntrospectionError, "Introspection failed: #{e.message}"
        end

        status = response.code.to_i

        if status == 429
          retry_after  = parse_float_header(response, "Retry-After")
          rl_limit     = parse_int_header(response, "X-RateLimit-Limit")
          rl_remaining = parse_int_header(response, "X-RateLimit-Remaining")
          rl_reset     = parse_int_header(response, "X-RateLimit-Reset")

          if attempt >= max_retries
            raise RateLimitError.new(
              "AgentAdmit rate limit exceeded. Max retries (#{max_retries}) exhausted.",
              retry_after: retry_after,
              limit: rl_limit,
              remaining: rl_remaining,
              reset: rl_reset
            )
          end

          # Compute wait: honor Retry-After header or use exponential backoff, cap at 30s
          wait_ms   = retry_after ? (retry_after * 1000).ceil : [delay_ms, 30_000].min
          jitter_ms = rand(0..500)
          total_ms  = wait_ms + jitter_ms

          warn "[AgentAdmit] Rate-limited (attempt #{attempt + 1}/#{max_retries}). " \
               "Retrying in #{total_ms}ms."

          sleep(total_ms / 1000.0)
          delay_ms = [delay_ms * 2, 30_000].min
          next
        end

        # Non-429 response — process normally
        case status
        when 200
          data = JSON.parse(response.body)

          # Check active flag (RFC 7662 introspection pattern).
          # The verify endpoint returns {active: false} with HTTP 200 for invalid/
          # expired/revoked tokens. Without this check, we'd read empty scopes.
          unless data["active"]
            reason = data["error"] || "invalid_token"
            raise InvalidTokenError, "Token is not active: #{reason}"
          end

          raise InvalidTokenError, "Introspection returned no user" if data["user_id"].nil?

          return IntrospectionResult.new(
            user_id:      data["user_id"],
            connection_id: data["connection_id"],
            scopes:       data["scopes"] || [],
            agent_label:  data["agent_label"] || "Unknown Agent"
          )
        when 401
          data = JSON.parse(response.body) rescue {}
          raise InvalidTokenError, data["error_description"] || "Token validation failed"
        else
          raise IntrospectionError, "Verification service returned #{response.code}"
        end
      end

      # Should never be reached
      raise IntrospectionError, "Unexpected exit from retry loop"
    end

    private

    def build_http(uri)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl     = uri.scheme == "https"
      http.read_timeout = 5
      http.open_timeout = 5
      http
    end

    def build_request(uri, token)
      req = Net::HTTP::Post.new(uri.path)
      req["Authorization"] = "Bearer #{@config.api_key}"
      req["Content-Type"]  = "application/json"
      req.body = JSON.generate({ token: token })
      req
    end

    ##
    # Parse a response header as Float, returning nil if absent or non-numeric.
    #
    def parse_float_header(response, name)
      val = response[name]
      return nil if val.nil? || val.empty?
      Float(val) rescue nil
    end

    ##
    # Parse a response header as Integer, returning nil if absent or non-numeric.
    #
    def parse_int_header(response, name)
      val = response[name]
      return nil if val.nil? || val.empty?
      Integer(val) rescue nil
    end
  end
end
