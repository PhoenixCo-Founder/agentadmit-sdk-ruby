# frozen_string_literal: true

module AgentAdmit
  ##
  # Caller-Identity Consent middleware: the "classify caller, then gate the
  # right independent path" recipe as one Rack middleware, so an app owner
  # does not have to hand-roll it.
  #
  # One endpoint serves every caller class. On each request the middleware:
  #
  #  1. classifies the caller from the STRUCTURE of the credential (a class
  #     the caller cannot self-select), before any consent check;
  #  2. routes to that class's ISOLATED consent path; no path reads or
  #     inherits another class's preference;
  #  3. permits or denies, and sets env variables
  #     (agentadmit.caller_class, agentadmit.consent, plus the standard agent
  #     env variables on the external-agent path).
  #
  #  - external_agent: an ag_at_ access token -> hosted introspection, which
  #    returns the external-agent consent verdict inline plus the granted
  #    scopes. Enforced here directly.
  #  - in_app_ai: your application's own server-side AI code path -> the
  #    Consent Ledger /consent/check for the in-app-AI class.
  #  - human_session: your application's own permission model (sharing,
  #    roles, grants). Deferred to your existing authorization by default;
  #    opt in to a stored human-session switch with gate_human: true.
  #
  # The three decisions are independent: granting one never grants another.
  #
  # SECURITY: this is a consent gate, not an authenticator. It classifies the
  # caller and enforces the per-class CONSENT decision; it does not by itself
  # authenticate a human session. Mount it AFTER your own authentication. On
  # the human_session path it defers to your application's permission model
  # and calls the app without re-authenticating. The external_agent path is
  # always authenticated (hosted introspection); the in_app_ai path always
  # evaluates the ledger.
  #
  # Usage:
  #   use AgentAdmit::CallerConsent,
  #       # derive the class from your own credential structure, never caller input
  #       classify_non_agent: ->(env) {
  #         env["HTTP_X_INTERNAL_AI"] == ENV["INTERNAL_AI_SECRET"] ? "in_app_ai" : "human_session"
  #       },
  #       resolve_data_owner_id: ->(env) { Rack::Request.new(env).params["owner_id"] },
  #       required_scope: "read:records"
  #
  class CallerConsent
    # RFC 7235: the auth-scheme token is case-insensitive.
    BEARER_AGENT_RE = /\Abearer ag_at_/i

    HUMAN_SESSION  = "human_session"
    IN_APP_AI      = "in_app_ai"
    EXTERNAL_AGENT = "external_agent"

    ##
    # @param app [#call] the downstream Rack app
    # @param resolve_data_owner_id [Proc, nil] env -> your app's identifier
    #   for the data owner whose resource is accessed. Required for the
    #   in_app_ai path, and for human_session when gate_human is set. The
    #   external-agent owner comes from the token, so it is not used there.
    # @param classify_non_agent [Proc, nil] env -> "in_app_ai" or
    #   "human_session", derived from the STRUCTURE of the credential (for
    #   example an internal service token), never a value the caller can set.
    #   Defaults to treating non-agent callers as human sessions.
    # @param required_scope [String, nil] for the external_agent path,
    #   require this scope (403 insufficient_scope if not granted).
    # @param scope_group [String, nil] optional finer-than-class consent
    #   group for ledger checks.
    # @param gate_human [Boolean] also gate the human_session class against a
    #   stored switch. Off by default: the human path belongs to your own
    #   permission model.
    #
    def initialize(app, resolve_data_owner_id: nil, classify_non_agent: nil,
                   required_scope: nil, scope_group: nil, gate_human: false)
      @app = app
      @client = IntrospectionClient.new
      @resolve_data_owner_id = resolve_data_owner_id
      @classify_non_agent = classify_non_agent
      @required_scope = required_scope
      @scope_group = scope_group
      @gate_human = gate_human
    end

    ##
    # Classify the caller from credential structure, before any consent
    # check. An ag_at_ bearer token is an external agent; anything else is
    # resolved by classify_non_agent (default: human_session). The class is
    # derived, never self-selected by the caller.
    #
    def classify_caller(env)
      auth = env["HTTP_AUTHORIZATION"] || ""
      return EXTERNAL_AGENT if BEARER_AGENT_RE.match?(auth)
      return IN_APP_AI if @classify_non_agent && @classify_non_agent.call(env) == IN_APP_AI

      HUMAN_SESSION
    end

    def call(env)
      caller_class = classify_caller(env)
      env["agentadmit.caller_class"] = caller_class

      case caller_class
      when EXTERNAL_AGENT
        call_external_agent(env)
      when IN_APP_AI
        call_ledger_gated(env, IN_APP_AI, "in_app_ai",
                          "The data owner has not enabled in-app AI analysis.")
      else
        if @gate_human
          call_ledger_gated(env, HUMAN_SESSION, "user",
                            "The data owner has not enabled this access.")
        else
          # Defer the human path to the app's existing authorization.
          env["agentadmit.auth_type"] = "user"
          @app.call(env)
        end
      end
    end

    private

    ##
    # External-agent path: hosted introspection carries the verdict and the
    # scopes. A present-and-denied verdict fails closed; an absent verdict
    # means the platform default (external-agent allowed) held.
    #
    def call_external_agent(env)
      token = (env["HTTP_AUTHORIZATION"] || "").sub(/\Abearer /i, "")

      begin
        result = @client.verify(token)
      rescue InvalidTokenError => e
        return json_error(401, "invalid_token", e.message)
      rescue IntrospectionError => e
        return json_error(502, "introspection_failed", e.message)
      end

      if @required_scope && !(result.scopes || []).include?(@required_scope)
        return [403, { "Content-Type" => "application/json" },
                [{ error: "insufficient_scope",
                   required_scope: @required_scope,
                   granted_scopes: result.scopes || [],
                   message: "This action requires '#{@required_scope}' scope." }.to_json]]
      end

      return json_error(403, "consent_not_granted",
                        "The data owner has not enabled external agent access.") unless result.consent_granted?

      env["agentadmit.auth_type"] = "agent"
      env["agentadmit.user_id"] = result.user_id
      env["agentadmit.scopes"] = result.scopes
      env["agentadmit.connection_id"] = result.connection_id
      env["agentadmit.agent_label"] = result.agent_label
      env["agentadmit.presence"] = result.presence
      env["agentadmit.consent"] = result.consent if result.consent

      @app.call(env)
    end

    ##
    # Token-less caller class (in_app_ai, or human_session under gate_human),
    # gated on the Consent Ledger. Fail closed: an unreachable or erroring
    # ledger denies, never allows.
    #
    def call_ledger_gated(env, caller_class, auth_type, denied_message)
      owner = @resolve_data_owner_id&.call(env)
      if owner.nil? || owner.empty?
        return json_error(500, "server_error",
                          "resolve_data_owner_id is required for this caller class")
      end

      begin
        verdict = @client.check_consent(app_user_id: owner, caller_class: caller_class,
                                        scope_group: @scope_group)
      rescue StandardError
        return json_error(503, "consent_unavailable", "Consent check failed")
      end

      return json_error(403, "consent_not_granted", denied_message) unless verdict["granted"] == true

      env["agentadmit.auth_type"] = auth_type
      env["agentadmit.consent"] = verdict
      @app.call(env)
    end

    def json_error(status, error, description)
      [status, { "Content-Type" => "application/json" },
       [{ error: error, error_description: description }.to_json]]
    end
  end
end
