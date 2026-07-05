# frozen_string_literal: true

require "net/http"
require "json"
require "uri"

module AgentAdmit
  ##
  # Mandatory introspection client -- validates tokens via AgentAdmit hosted service.
  # No local JWT decode. Every verification call goes through AgentAdmit.
  #
  class IntrospectionClient
    # Hard cap on any single retry wait -- including a server-supplied Retry-After.
    MAX_RETRY_WAIT_MS = 30_000
    # Hard cap on cumulative wait across all retries of a single verify call.
    MAX_RETRY_BUDGET_MS = 120_000

    IntrospectionResult = Struct.new(:user_id, :connection_id, :scopes, :agent_label,
                                     :sub, :role, :app_id, :jti, :exp, :consent,
                                     :presence, keyword_init: true) do
      def has_scope?(scope)
        scopes.include?(scope)
      end

      # Consent Ledger verdict for the external-agent path (additive; may be
      # nil). A denied verdict means the app returns its own 403 -- the token
      # itself stays valid (consent is orthogonal to revocation).
      #
      # Contract (matches the PHP and Java SDKs): an ABSENT consent block
      # means a legacy server that never sends one -- treated as allowed,
      # which is also the platform default for the external-agent class. A
      # PRESENT block grants only on an explicit boolean true; a missing or
      # non-boolean granted value is treated as denied (malformed = deny).
      def consent_granted?
        return true if consent.nil?
        consent["granted"] == true
      end

      # Human-presence fact from the WebAuthn step-up (additive; may be nil).
      # True ONLY when the connection was authorized by a human who completed
      # a presence ceremony on the consent page: verified must be the boolean
      # true. Unlike consent, absence fails closed -- older servers never send
      # the block, and connections minted without a ceremony carry
      # verified: false, so nil/false/malformed all read as not verified.
      def presence_verified?
        presence.is_a?(Hash) && presence["verified"] == true
      end
    end

    def initialize(config = nil)
      @config = config || AgentAdmit.configuration || Config.new
      @config.validate_api_key!
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
      waited_ms   = 0    # cumulative wait across retries

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

          # Compute wait: Retry-After beats exponential backoff, but both are
          # capped -- Retry-After is untrusted server input and must not pin
          # the caller.
          requested_ms = retry_after ? (retry_after * 1000).ceil : delay_ms
          wait_ms   = [[requested_ms, 0].max, MAX_RETRY_WAIT_MS].min
          jitter_ms = rand(0..500)
          total_ms  = wait_ms + jitter_ms

          if waited_ms + total_ms > MAX_RETRY_BUDGET_MS
            raise RateLimitError.new(
              "AgentAdmit rate limit retry budget (#{MAX_RETRY_BUDGET_MS / 1000}s) exhausted.",
              retry_after: retry_after,
              limit: rl_limit,
              remaining: rl_remaining,
              reset: rl_reset
            )
          end
          waited_ms += total_ms

          warn "[AgentAdmit] Rate-limited (attempt #{attempt + 1}/#{max_retries}). " \
               "Retrying in #{total_ms}ms."

          sleep(total_ms / 1000.0)
          delay_ms = [delay_ms * 2, 30_000].min
          next
        end

        # Non-429: only treat 2xx as a candidate for a valid token.
        unless (200..299).cover?(status)
          if status == 401
            data = JSON.parse(response.body) rescue {}
            raise InvalidTokenError, data["error_description"] || "Token validation failed"
          end
          raise IntrospectionError, "Verification service returned #{response.code}"
        end

        # 2xx -- parse and strictly validate the response body.
        data = begin
          JSON.parse(response.body)
        rescue JSON::ParserError
          raise IntrospectionError, "Introspection response is not valid JSON"
        end

        # active must be strictly true (boolean).
        unless data["active"] == true
          reason = data["error"] || "invalid_token"
          raise InvalidTokenError.new("Token is not active: #{reason}", code: reason)
        end

        # insufficient_scope arrives with active: true (token valid,
        # requested scope not granted).
        if data["error"] == "insufficient_scope"
          raise InsufficientScopeError, data["error_description"] || "Scope not granted"
        end

        # Validate that consumed fields have the expected types when present.
        validate_introspection_types!(data)

        # Keep any PRESENT consent hash, even with a malformed granted value:
        # coercing it to nil would read as "legacy server, allowed" in
        # consent_granted?, silently failing open. A malformed verdict must
        # stay visible so consent_granted? can deny it.
        consent = data["consent"]
        consent = nil unless consent.is_a?(Hash)

        # Presence rides along when the platform returns it. Same strictness
        # as active: verified must be the boolean true or false, never coerced.
        # Unlike consent, a malformed block is dropped -- presence_verified?
        # fails closed on nil, so dropping cannot fail open.
        presence = data["presence"]
        presence = nil unless presence.is_a?(Hash) && [true, false].include?(presence["verified"])

        return IntrospectionResult.new(
          user_id:      data["user_id"],
          connection_id: data["connection_id"],
          scopes:       data["scopes"] || [],
          agent_label:  data["agent_label"] || "Unknown Agent",
          sub:          data["sub"],
          role:         data["role"],
          app_id:       data["app_id"],
          jti:          data["jti"],
          exp:          data["exp"],
          consent:      consent,
          presence:     presence
        )
      end

      # Should never be reached
      raise IntrospectionError, "Unexpected exit from retry loop"
    end

    CALLER_CLASSES = %w[human_session in_app_ai external_agent].freeze

    ##
    # Ask the Consent Ledger whether a caller class may act on a user's data.
    # Decision point for the token-less caller classes (human_session,
    # in_app_ai); external agents get the same verdict on the verify result.
    #
    # @param app_user_id [String] your app's identifier for the data owner
    # @param caller_class [String] "human_session" | "in_app_ai" | "external_agent"
    # @param scope_group [String, nil] optional finer-than-class group
    # @return [Hash] verdict: granted, caller_class, scope_group, source, evaluated_at
    # @raise [ArgumentError] unknown caller_class
    # @raise [IntrospectionError] hosted service unreachable or rejected the call
    #
    def check_consent(app_user_id:, caller_class:, scope_group: nil)
      unless CALLER_CLASSES.include?(caller_class)
        raise ArgumentError, "caller_class must be one of #{CALLER_CLASSES.join(', ')}"
      end

      uri  = URI.parse("#{@config.api_url.sub(%r{/\z}, '')}/api/v1/consent/check")
      http = build_http(uri)

      request = Net::HTTP::Post.new(uri.path)
      request["Authorization"] = "Bearer #{@config.api_key}"
      request["Content-Type"]  = "application/json"
      body = { app_user_id: app_user_id, caller_class: caller_class }
      body[:scope_group] = scope_group if scope_group
      request.body = JSON.generate(body)

      response = begin
        http.request(request)
      rescue StandardError => e
        raise IntrospectionError, "Consent check failed: #{e.message}"
      end

      unless (200..299).cover?(response.code.to_i)
        data = JSON.parse(response.body) rescue {}
        raise IntrospectionError,
              data["error_description"] || data["error"] || "Consent check returned #{response.code}"
      end

      # 2xx -- parse strictly; a garbage body must not read as an empty verdict.
      begin
        JSON.parse(response.body)
      rescue JSON::ParserError
        raise IntrospectionError, "Consent check response is not valid JSON"
      end
    end

    private

    ##
    # Enforce that the fields the middleware relies on have the correct types.
    # Any type mismatch means we cannot safely use the response -- treat as invalid.
    #
    # @raise [InvalidTokenError]
    #
    def validate_introspection_types!(data)
      # user_id is required and must be a String.
      unless data["user_id"].is_a?(String)
        raise InvalidTokenError, "Introspection returned no user"
      end

      # agent_id, connection_id -- must be String when present.
      %w[agent_id connection_id].each do |field|
        val = data[field]
        next if val.nil?
        unless val.is_a?(String)
          raise InvalidTokenError, "Introspection field '#{field}' must be a String"
        end
      end

      # scopes -- must be Array of Strings when present.
      if data.key?("scopes")
        scopes = data["scopes"]
        unless scopes.is_a?(Array) && scopes.all? { |s| s.is_a?(String) }
          raise InvalidTokenError, "Introspection field 'scopes' must be an Array of Strings"
        end
      end
    end

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
