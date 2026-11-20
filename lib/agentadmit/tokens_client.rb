# frozen_string_literal: true

require "net/http"
require "json"
require "uri"
require "erb"

module AgentAdmit
  ##
  # TokensClient — issue, exchange, and revoke connection tokens via the
  # AgentAdmit hosted service.
  #
  class TokensClient
    # Sentinel for issue_token's duration_seconds: leave the field out of the
    # request entirely, so AgentAdmit applies its default (30 days). Pass nil
    # instead for an until-revoked connection (explicit JSON null).
    UNSET = Object.new.freeze

    # Maximum length of a declared purpose (matches the hosted API contract).
    PURPOSE_MAX_LENGTH = 300

    # Maximum length of a user-declared intent (matches the hosted API
    # contract: optional string, 1..300 characters).
    USER_INTENT_MAX_LENGTH = 300

    def initialize(config = nil)
      @config = config || AgentAdmit.configuration || Config.new
      @config.validate_api_key!
    end

    ##
    # Issue a connection token for one of your users.
    # Calls POST /api/v1/apps/{app_id}/token.
    #
    # The duration is tri-state:
    # - omit the argument — field omitted; AgentAdmit applies its default
    #   (30 days)
    # - nil — explicit JSON null; the connection lasts until revoked
    # - Integer — explicit duration in seconds (60–31536000)
    #
    # @param user_id [String] your app's identifier for the user
    # @param scopes [Array<String>] scopes the connection grants
    # @param role [String, nil] the user's role on the connection
    # @param duration_seconds [Integer, nil, UNSET] see above
    # @param purpose [String, nil] declared purpose: the user-facing reason
    #   recorded on the grant at the consent moment. Review-time record only,
    #   never an enforcement input; authorization decisions ride scopes,
    #   connection status, and consent. Max 300 characters; omitted from the
    #   request when nil.
    # @param user_intent [String, nil] user-declared intent: the user's OWN
    #   words, typed at the consent moment (distinct from purpose, which is
    #   the app's words). Optional, 1-300 characters. Validated like purpose:
    #   a non-String, non-nil value or a string over 300 characters raises
    #   ArgumentError before any request is sent — silently discarding the
    #   user's typed words would be data loss. Empty/whitespace-only strings
    #   normalize to nil and are omitted. Like purpose, it is a review-time
    #   record, never an enforcement input.
    # @param presence [AppAttestedPresence, nil] app-attested ceremony fact:
    #   set it AFTER verifying and consuming your app's own fresh,
    #   purpose-bound WebAuthn/passkey attestation for this mint. Forwarded
    #   as presence {verified: true, uv: true, method, verified_at} and
    #   stored provenance-marked "app:<method>"; omitted when nil (omitting
    #   the field is the only way to say "no ceremony").
    # @return [Hash] the issue response — "token" is the self-describing
    #   ag_ct_… connection token to hand to the user's agent
    # @raise [ArgumentError] if purpose exceeds 300 characters, if
    #   user_intent is a non-String (other than nil) or exceeds 300
    #   characters, or if presence is neither nil nor an AppAttestedPresence
    # @raise [IntrospectionError] if issuance fails
    #
    def issue_token(user_id:, scopes:, role: nil, duration_seconds: UNSET, purpose: nil,
                    user_intent: nil, presence: nil)
      if purpose && purpose.length > PURPOSE_MAX_LENGTH
        raise ArgumentError, "purpose must be at most #{PURPOSE_MAX_LENGTH} characters"
      end

      # User-declared intent is validated like purpose: reject out-of-contract
      # values before any request rather than silently discarding the user's
      # typed words (data loss). Empty/whitespace-only normalizes to nil-omit.
      unless user_intent.nil? || user_intent.is_a?(String)
        raise ArgumentError, "user_intent must be a String or nil"
      end
      if user_intent && user_intent.length > USER_INTENT_MAX_LENGTH
        raise ArgumentError, "user_intent must be at most #{USER_INTENT_MAX_LENGTH} characters"
      end
      user_intent = nil if user_intent && user_intent.strip.empty?

      # Presence is typed-only: a raw Hash is rejected so the wire contract
      # (literal-true verified/uv, offset-carrying verified_at) stays owned
      # by AppAttestedPresence, never hand-rolled at call sites.
      unless presence.nil? || presence.is_a?(AppAttestedPresence)
        raise ArgumentError, "presence must be an AgentAdmit::AppAttestedPresence or nil"
      end

      body = { "user_id" => user_id, "scopes" => scopes }
      body["role"] = role if role
      body["purpose"] = purpose if purpose
      body["user_intent"] = user_intent if user_intent
      body["presence"] = presence.to_wire if presence
      # Tri-state: the UNSET sentinel omits the key entirely; nil survives
      # JSON.generate as explicit JSON null (no compact, no nil-guard).
      body["duration_seconds"] = duration_seconds unless duration_seconds.equal?(UNSET)

      post("/api/v1/apps/#{@config.app_id}/token", body, authenticated: true, op: "issue_token")
    end

    ##
    # Exchange a single-use connection token for an access token.
    # Calls POST /api/v1/exchange — unauthenticated by design: the connection
    # token itself is the credential, so the operator API key is NOT sent.
    #
    # @param connection_token [String] the ag_ct_… connection token
    # @param agent_label [String, nil] human-readable agent name
    # @param agent_id [String, nil] agent identifier
    # @param agent_platform [String, nil] the agent app or runtime the agent
    #   says it runs in (reported by the agent, unverified)
    # @param agent_model [Hash, nil] the AI model the agent says it runs on:
    #   {"id" => String, "version" => String (optional)} (reported by the
    #   agent, unverified). The hosted service records both and never lets
    #   them decide the outcome of the exchange.
    # @return [Hash] the exchange response — "access_token" is the ag_at_… token
    # @raise [IntrospectionError] if the exchange fails
    #
    def exchange(connection_token, agent_label: nil, agent_id: nil,
                 agent_platform: nil, agent_model: nil)
      body = { "token" => connection_token }
      body["agent_label"] = agent_label if agent_label
      body["agent_id"] = agent_id if agent_id
      body["agent_platform"] = agent_platform if agent_platform
      body["agent_model"] = agent_model if agent_model

      post("/api/v1/exchange", body, authenticated: false, op: "exchange")
    end

    ##
    # Revoke a connection (and its access tokens).
    # Calls POST /api/v1/revoke.
    #
    # @param connection_id [String] the connection to revoke
    # @param reason [String, nil] optional human-readable reason
    # @return [Hash] the revoke response — { "ok" => true, ... }
    # @raise [IntrospectionError] if the revocation fails
    #
    def revoke(connection_id, reason: nil)
      body = { "connection_id" => connection_id }
      body["reason"] = reason if reason

      post("/api/v1/revoke", body, authenticated: true, op: "revoke")
    end

    # Shortest action_session_id the hosted service accepts (asess_ + id).
    ACTION_SESSION_ID_MIN_LENGTH = 20
    # Longest app_user_id the hosted service accepts.
    APP_USER_ID_MAX_LENGTH = 255

    ##
    # Open a pending confirmation for your own signed-in user (SDK 1.15.0).
    # Calls POST /api/v1/action-sessions/{action_session_id}/owner-link with
    # the app's API key and { "app_user_id" => ... }.
    #
    # When a scope needs a fresh human confirmation and the user has no
    # passkey on file for the app yet (confirmation["enrollment_required"]
    # is true), the link the agent holds cannot be used alone. Send the
    # signed-in user to the returned "owner_session_url": on that page they
    # create a passkey and confirm the action; on a computer the page can
    # show a QR code to continue on the user's phone.
    #
    # Two rules: call this only from a route your signed-in human uses,
    # passing that user's id; never return "owner_session_url" to an agent
    # (whoever opens it can create the passkey that confirms the action), and
    # never log it. The SDK does not mount this on any middleware or route.
    #
    # @param action_session_id [String] confirmation["action_session_id"]
    #   from the confirmation_required refusal
    # @param app_user_id [String] the id of the user your backend has signed
    #   in; it must be the user the confirmation is for
    # @return [Hash] "action_session_id", "owner_session_url",
    #   "enrollment_required" (true/false), "expires_at", and
    #   "enrollment_reason" ("no_passkey" or "no_eligible_authenticator")
    #   only when "enrollment_required" is true
    # @raise [ArgumentError] on a bad argument, before any request
    # @raise [ApiError] on any error status (no retry) or a malformed 2xx body
    # @raise [IntrospectionError] when the hosted service cannot be reached
    #
    def create_owner_link(action_session_id:, app_user_id:)
      unless action_session_id.is_a?(String) && action_session_id.start_with?("asess_") &&
             action_session_id.length >= ACTION_SESSION_ID_MIN_LENGTH
        raise ArgumentError, "action_session_id must be the action_session_id from the confirmation block (asess_...)"
      end
      unless app_user_id.is_a?(String) && !app_user_id.empty? && app_user_id.length <= APP_USER_ID_MAX_LENGTH
        raise ArgumentError, "app_user_id must be a non-empty String of at most #{APP_USER_ID_MAX_LENGTH} characters"
      end

      path = "/api/v1/action-sessions/#{path_segment(action_session_id)}/owner-link"
      response = send_post(path, { "app_user_id" => app_user_id }, authenticated: true, op: "create_owner_link")
      status = response.code.to_i
      parsed = begin
        JSON.parse(response.body.to_s)
      rescue JSON::ParserError
        nil
      end
      body = parsed.is_a?(Hash) ? parsed : {}

      unless status >= 200 && status < 300
        code = body["error"].is_a?(String) ? body["error"] : nil
        raise ApiError.new("create_owner_link returned #{status}#{code ? " #{code}" : ''}", status: status, code: code)
      end

      enrollment = body["enrollment_required"]
      unless body["owner_session_url"].is_a?(String) && (enrollment == true || enrollment == false) &&
             body["action_session_id"].is_a?(String) && body["expires_at"].is_a?(String)
        # The body is not attached: it may hold a partial owner link.
        raise ApiError.new("create_owner_link returned a malformed response", status: status)
      end

      link = { "action_session_id" => body["action_session_id"],
               "owner_session_url" => body["owner_session_url"],
               "enrollment_required" => enrollment,
               "expires_at" => body["expires_at"] }
      link["enrollment_reason"] = body["enrollment_reason"] if enrollment && body["enrollment_reason"].is_a?(String)
      link
    end

    private

    # Percent-encodes one path segment (space as %20, never "+").
    def path_segment(value)
      ERB::Util.url_encode(value)
    end

    def build_http(uri)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == "https"
      http.read_timeout = 10
      http.open_timeout = 10
      http
    end

    # Sends one POST and returns the Net::HTTP response; a transport failure
    # raises IntrospectionError, exactly like the other calls on this client.
    def send_post(path, body, authenticated:, op:)
      uri = URI.parse("#{@config.api_url.chomp('/')}#{path}")
      http = build_http(uri)

      request = Net::HTTP::Post.new(uri.path)
      request["Content-Type"] = "application/json"
      if authenticated
        # No Authorization on /exchange — the connection token is the credential.
        request["Authorization"] = "Bearer #{@config.api_key}"
        request["X-App-Id"] = @config.app_id
      end
      request.body = JSON.generate(body)

      begin
        http.request(request)
      rescue StandardError => e
        raise IntrospectionError, "#{op} failed: #{e.message}"
      end
    end

    def post(path, body, authenticated:, op:)
      response = send_post(path, body, authenticated: authenticated, op: op)
      status = response.code.to_i
      raise IntrospectionError, "#{op} returned #{status}" if status >= 400

      JSON.parse(response.body)
    rescue JSON::ParserError
      raise IntrospectionError, "#{op} returned an unparseable response"
    end
  end
end
