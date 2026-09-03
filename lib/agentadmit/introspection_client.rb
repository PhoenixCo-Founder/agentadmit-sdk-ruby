# frozen_string_literal: true

require "net/http"
require "json"
require "uri"
require "digest"

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

    # Confirm-each-time (1.11.0). Request header an agent sets on its retry
    # after the human completed the hosted confirmation ceremony, and the
    # Rack env key Rack exposes it under.
    ACTION_ATTESTATION_HEADER   = "X-AgentAdmit-Action-Attestation"
    ACTION_ATTESTATION_RACK_KEY = "HTTP_X_AGENTADMIT_ACTION_ATTESTATION"

    # Hosted BodySchema caps on the verify route for the confirm-each-time
    # fields (endpoint <=500 and method <=20 are enforced elsewhere).
    ATTESTATION_MAX = 120
    DIGEST_MAX      = 128
    SUMMARY_MAX     = 200

    IntrospectionResult = Struct.new(:user_id, :connection_id, :scopes, :agent_label,
                                     :sub, :role, :app_id, :jti, :exp, :consent,
                                     :presence, :purpose, :user_intent,
                                     :action_confirmation, keyword_init: true) do
      def has_scope?(scope)
        scopes.include?(scope)
      end

      # Consent Ledger verdict for the external-agent path (additive; may be
      # nil). A denied verdict means the app returns its own 403 -- the token
      # itself stays valid (consent is orthogonal to revocation).
      #
      # Contract: grants ONLY on an explicit boolean true. An ABSENT block is
      # NEVER a grant -- the hosted service deliberately omits it when its
      # consent-store read fails (designed degraded mode), so absence here
      # fails closed. A missing or non-boolean granted value is likewise
      # denied (malformed = deny). Callers that want the authoritative answer
      # for an absent/malformed verdict should resolve it through
      # #check_consent for the external_agent class (CallerConsent does this
      # automatically).
      def consent_granted?
        consent.is_a?(Hash) && consent["granted"] == true
      end

      # Human-presence fact from the WebAuthn step-up (additive; may be nil).
      # True ONLY when the connection was authorized by a human who completed
      # a presence ceremony on the consent page: verified must be the boolean
      # true. Absence fails closed -- older servers never send the block, and
      # connections minted without a ceremony carry verified: false, so
      # nil/false/malformed all read as not verified.
      def presence_verified?
        presence.is_a?(Hash) && presence["verified"] == true
      end

      # `purpose` (String or nil) is the declared purpose: the user-facing
      # reason recorded on the grant at the consent moment. Review-time record
      # only, never an enforcement input; authorization decisions ride scopes,
      # connection status, and consent.

      # `user_intent` (String or nil) is the user-declared intent: the user's
      # OWN words, typed at the consent moment (purpose is the app's words;
      # user_intent is the user's). Review-time record only, never an
      # enforcement input; authorization decisions ride scopes, connection
      # status, and consent.

      # `action_confirmation` (Hash or nil) is the confirm-each-time
      # attestation the hosted service CONSUMED to accept this call:
      # {"action_session_id" => String, "consumed" => true}. Present only
      # when a fresh human confirmation was spent on exactly this action, and
      # only when the block is strictly typed -- anything else is dropped. An
      # app that runs its own transaction step-up can treat this as that
      # confirmation instead of asking the human twice.
      def action_confirmed?
        action_confirmation.is_a?(Hash) && action_confirmation["consumed"] == true
      end
    end

    class << self
      ##
      # `sha256:<hex>` over the RAW request body bytes, so a confirmation
      # covers the exact payload and not merely the route. nil for an empty
      # or absent body (the field is then omitted, never sent as null).
      #
      # @param body [String, nil] raw request body bytes
      # @return [String, nil]
      #
      def request_digest_for(body)
        return nil unless body.is_a?(String) && !body.empty?

        "sha256:#{Digest::SHA256.hexdigest(body)}"
      end

      ##
      # A strictly-typed copy of the wire `confirmation` block, or nil when
      # it is malformed. ids/urls/expiry/scope must be Strings; method,
      # endpoint, request_digest and summary are nullable Strings (anything
      # else reads as nil). Nothing outside the contract is copied through.
      #
      # @param raw [Object] the `confirmation` value from the hosted response
      # @return [Hash, nil]
      #
      def parse_action_confirmation(raw)
        return nil unless raw.is_a?(Hash)
        return nil unless %w[action_session_id action_session_url expires_at scope]
                          .all? { |key| raw[key].is_a?(String) }

        nullable = ->(value) { value.is_a?(String) ? value : nil }
        { "action_session_id"  => raw["action_session_id"],
          "action_session_url" => raw["action_session_url"],
          "expires_at"         => raw["expires_at"],
          "scope"              => raw["scope"],
          "method"             => nullable.call(raw["method"]),
          "endpoint"           => nullable.call(raw["endpoint"]),
          "request_digest"     => nullable.call(raw["request_digest"]),
          "summary"            => nullable.call(raw["summary"]) }
      end

      ##
      # The agent's X-AgentAdmit-Action-Attestation header from a Rack env:
      # first value only, trimmed, capped at 120 characters. nil when absent
      # or empty, so the field is omitted from the verify body.
      #
      # @param env [Hash] the Rack env
      # @return [String, nil]
      #
      def action_attestation_from_env(env)
        return nil unless env.is_a?(Hash)

        raw = env[ACTION_ATTESTATION_RACK_KEY]
        raw = raw.first if raw.is_a?(Array)
        return nil unless raw.is_a?(String)

        # Rack folds a repeated header into one comma-joined String; an
        # attestation id is a single opaque value, so take the first.
        value = raw.split(",").first.to_s.strip
        value.empty? ? nil : value[0, ATTESTATION_MAX]
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
    # Per-call audit telemetry (all optional, all omitted from the request
    # body when unknown -- never sent as null or empty string):
    #
    # @param token [String] The full token including ag_at_ prefix
    # @param scope_used [String, nil] the single scope this call enforces
    #   (from the scope-enforcing integration point). Never a joined list;
    #   omit for bare auth resolution / presence-only gates.
    # @param endpoint [String, nil] inbound request path. Sent path-only:
    #   the query string is stripped (queries can carry PII) and the path is
    #   truncated to 500 characters.
    # @param method [String, nil] inbound HTTP method; sent uppercased,
    #   capped at 20 characters.
    # @param action_attestation_id [String, nil] confirm-each-time (1.11.0):
    #   the single-use attestation id from a completed hosted ceremony, which
    #   the agent presents on its retry via the
    #   X-AgentAdmit-Action-Attestation header. Capped at 120 characters.
    # @param request_digest [String, nil] `sha256:<hex>` over the raw request
    #   body, so the confirmation covers the exact payload, not just the
    #   route. Capped at 128 characters.
    # @param action_summary [String, nil] the app's plain-language
    #   description of THIS action, shown to the human on the hosted
    #   confirmation page and committed into the signature. Trimmed and
    #   capped at 200 characters. AgentAdmit does not verify the summary
    #   against the request; it proves what the human was shown.
    # @return [IntrospectionResult]
    # @raise [InvalidTokenError] if validation fails
    # @raise [ActiveDenialError] (incl. {InsufficientScopeError},
    #   {BoundExceededError}, {ConfirmationRequiredError}) if the response is
    #   active but carries an error string -- the service refused this call;
    #   always a denial
    # @raise [IntrospectionError] if the service is unreachable
    # @raise [RateLimitError] if rate-limited and retries exhausted
    #
    def verify(token, scope_used: nil, endpoint: nil, method: nil, consent_first: false,
               action_attestation_id: nil, request_digest: nil, action_summary: nil)
      unless token.start_with?(@config.token_prefix_access)
        raise InvalidTokenError, "Not an AgentAdmit access token"
      end

      max_retries = @config.respond_to?(:max_retries) ? @config.max_retries.to_i : 3
      delay_ms    = 1000 # initial backoff in milliseconds
      waited_ms   = 0    # cumulative wait across retries

      uri  = URI.parse(@config.verify_url)
      http = build_http(uri)

      (0..max_retries).each do |attempt|
        request = build_request(uri, token, scope_used: scope_used,
                                endpoint: endpoint, method: method,
                                consent_first: consent_first,
                                action_attestation_id: action_attestation_id,
                                request_digest: request_digest,
                                action_summary: action_summary)

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

        # Active-error fail-closed: `active: true` with a string `error`
        # means the token is valid but the authorization service refused
        # THIS call (insufficient_scope, bound_exceeded, or anything the
        # service may add later). Every such response is a DENIAL, never a
        # pass-through -- unknown error strings included.
        if data["error"].is_a?(String) && !data["error"].empty?
          raise_active_denial!(data, scope_used)
        end

        # Validate that consumed fields have the expected types when present.
        validate_introspection_types!(data)

        # Keep the consent block only when it is a Hash; anything else reads
        # as nil. Absent and malformed are both safe: neither is ever a grant
        # (consent_granted? fails closed, and CallerConsent resolves the
        # authoritative verdict through the Consent Ledger).
        consent = data["consent"]
        consent = nil unless consent.is_a?(Hash)

        # Presence rides along when the platform returns it. Same strictness
        # as active: verified must be the boolean true or false, never coerced.
        # A malformed block is dropped -- presence_verified? fails closed on
        # nil, so dropping cannot fail open.
        presence = data["presence"]
        presence = nil unless presence.is_a?(Hash) && [true, false].include?(presence["verified"])

        # Declared purpose passes through as-is when it is a String (the
        # hosted /verify returns it nullable). It is a review-time record,
        # never an enforcement input, so a malformed value is simply dropped.
        purpose = data["purpose"]
        purpose = nil unless purpose.is_a?(String)

        # User-declared intent passes through the same way (the hosted
        # /verify returns it nullable). Review-time record, never an
        # enforcement input, so a malformed value is simply dropped.
        user_intent = data["user_intent"]
        user_intent = nil unless user_intent.is_a?(String)

        # Confirm-each-time (1.11.0): the confirmation this accepted call
        # SPENT. Strict -- a String session id and a literal boolean true
        # consumed flag, or the block is dropped entirely. Surfacing a
        # half-formed block would let an app skip its own step-up on a
        # confirmation that was never actually consumed.
        action_confirmation = data["action_confirmation"]
        action_confirmation =
          if action_confirmation.is_a?(Hash) &&
             action_confirmation["action_session_id"].is_a?(String) &&
             action_confirmation["consumed"] == true
            { "action_session_id" => action_confirmation["action_session_id"],
              "consumed" => true }
          end

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
          presence:     presence,
          purpose:      purpose,
          user_intent:  user_intent,
          action_confirmation: action_confirmation
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

    ##
    # Map an active-response error string to its typed denial (always raises).
    #
    #  - insufficient_scope: token valid, enforced scope not granted. Carries
    #    the step-up fields: required_scope from the hosted response when
    #    present, else the scope this call enforced; granted_scopes from the
    #    hosted response when present.
    #  - bound_exceeded: the hosted bounded-capabilities layer refused the
    #    call; hosted fields ride along verbatim on the error's data.
    #  - confirmation_required: the scope IS granted but this call needs a
    #    fresh human confirmation; the staged ceremony rides along, strictly
    #    typed, so the agent can hand the link to the human. A malformed
    #    ceremony block degrades to the generic denial -- fail closed rather
    #    than relay an unusable confirmation.
    #  - anything else: unknown refusal -> generic typed denial. Fail closed.
    #
    def raise_active_denial!(data, scope_used)
      case data["error"]
      when "insufficient_scope"
        required = data["required_scope"].is_a?(String) ? data["required_scope"] : scope_used
        granted  = data["granted_scopes"]
        granted  = data["scopes"] unless granted.is_a?(Array)
        granted  = nil unless granted.is_a?(Array)
        raise InsufficientScopeError.new(
          data["error_description"] || "Scope not granted",
          required_scope: required, granted_scopes: granted, data: data
        )
      when "bound_exceeded"
        raise BoundExceededError.new(
          data["error_description"] || "Call refused by the authorization service.",
          data: data
        )
      when "confirmation_required"
        confirmation = self.class.parse_action_confirmation(data["confirmation"])
        if confirmation
          description = data["error_description"]
          description = ConfirmationRequiredError::DESCRIPTION unless
            description.is_a?(String) && !description.empty?
          status = data["attestation_status"]
          raise ConfirmationRequiredError.new(
            description,
            confirmation: confirmation,
            attestation_status: status.is_a?(String) ? status : nil,
            data: data
          )
        end
        # Malformed ceremony: fall through to the generic denial below.
        raise ActiveDenialError.new(
          "Call refused by the authorization service.",
          code: "confirmation_required", data: data
        )
      else
        raise ActiveDenialError.new(
          "Call refused by the authorization service.",
          code: data["error"], data: data
        )
      end
    end

    ##
    # Build the introspection POST. Beyond the token, the body carries the
    # per-call audit telemetry when known: scope_used (the single scope this
    # call enforces), endpoint (path only -- query stripped, queries can
    # carry PII -- truncated to 500 chars), method (uppercase, capped at
    # 20). Unknown fields are OMITTED, never sent as null or empty string --
    # the hosted audit row then honestly records "not reported".
    #
    # Confirm-each-time (1.11.0) adds three more optional fields under the
    # same rule: action_attestation_id (<=120), request_digest (<=128) and
    # action_summary (trimmed, <=200).
    #
    def build_request(uri, token, scope_used: nil, endpoint: nil, method: nil,
                      consent_first: false, action_attestation_id: nil,
                      request_digest: nil, action_summary: nil)
      req = Net::HTTP::Post.new(uri.path)
      req["Authorization"] = "Bearer #{@config.api_key}"
      req["Content-Type"]  = "application/json"

      body = { token: token }
      scope = presence_of(scope_used)
      body[:scope_used] = scope if scope
      path = normalize_endpoint(endpoint)
      body[:endpoint] = path if path
      verb = presence_of(method)
      body[:method] = verb.upcase[0, 20] if verb
      body[:consent_first] = true if consent_first

      attestation = trimmed_presence_of(action_attestation_id)
      body[:action_attestation_id] = attestation[0, ATTESTATION_MAX] if attestation
      digest = presence_of(request_digest)
      body[:request_digest] = digest[0, DIGEST_MAX] if digest
      summary = trimmed_presence_of(action_summary)
      body[:action_summary] = summary[0, SUMMARY_MAX] if summary

      req.body = JSON.generate(body)
      req
    end

    # The value when it is a non-empty String, else nil (field omitted).
    def presence_of(value)
      value.is_a?(String) && !value.empty? ? value : nil
    end

    # Same, after stripping surrounding whitespace (agent-supplied header
    # values and app-supplied summaries both arrive padded).
    def trimmed_presence_of(value)
      presence_of(value.is_a?(String) ? value.strip : nil)
    end

    # Path only: strip everything from the first "?" (query strings can
    # carry PII) and cap at 500 characters. nil when nothing usable remains
    # so the field is omitted, never null.
    def normalize_endpoint(endpoint)
      path = presence_of(endpoint)
      return nil unless path

      path = path.split("?", 2).first
      return nil if path.nil? || path.empty?

      path[0, 500]
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
