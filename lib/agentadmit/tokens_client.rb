# frozen_string_literal: true

require "net/http"
require "json"
require "uri"

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
    # @return [Hash] the exchange response — "access_token" is the ag_at_… token
    # @raise [IntrospectionError] if the exchange fails
    #
    def exchange(connection_token, agent_label: nil, agent_id: nil)
      body = { "token" => connection_token }
      body["agent_label"] = agent_label if agent_label
      body["agent_id"] = agent_id if agent_id

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

    private

    def post(path, body, authenticated:, op:)
      uri = URI.parse("#{@config.api_url.chomp('/')}#{path}")
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == "https"
      http.read_timeout = 10
      http.open_timeout = 10

      request = Net::HTTP::Post.new(uri.path)
      request["Content-Type"] = "application/json"
      if authenticated
        # No Authorization on /exchange — the connection token is the credential.
        request["Authorization"] = "Bearer #{@config.api_key}"
        request["X-App-Id"] = @config.app_id
      end
      request.body = JSON.generate(body)

      begin
        response = http.request(request)
      rescue StandardError => e
        raise IntrospectionError, "#{op} failed: #{e.message}"
      end

      status = response.code.to_i
      raise IntrospectionError, "#{op} returned #{status}" if status >= 400

      JSON.parse(response.body)
    rescue JSON::ParserError
      raise IntrospectionError, "#{op} returned an unparseable response"
    end
  end
end
