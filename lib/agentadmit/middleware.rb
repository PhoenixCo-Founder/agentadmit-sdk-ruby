# frozen_string_literal: true

module AgentAdmit
  ##
  # Rack middleware that intercepts requests with ag_at_ tokens
  # and validates them via introspection.
  #
  # Sets env variables for downstream use:
  #   env['agentadmit.auth_type']     -- "agent" or nil
  #   env['agentadmit.user_id']       -- validated user ID
  #   env['agentadmit.scopes']        -- granted scopes array
  #   env['agentadmit.connection_id'] -- connection identifier
  #   env['agentadmit.agent_label']   -- agent display name
  #   env['agentadmit.presence']      -- human-presence block (Hash) or nil
  #
  # Every verify call carries per-call audit telemetry: the request path
  # (PATH_INFO -- no query string) and the uppercase HTTP method, plus the
  # scope the call enforces when the middleware is mounted with one:
  #
  #   # scope resolved per request (env -> scope String or nil) ...
  #   use AgentAdmit::Middleware, scope_for: ->(env) { SCOPES[env["PATH_INFO"]] }
  #   # ... or one static scope for everything behind this middleware
  #   use AgentAdmit::Middleware, scope_for: "read:orders"
  #
  # When no scope is known the field is omitted (never null) and the hosted
  # audit row records "not reported". The local ScopeEnforcement checks
  # remain unchanged -- defense in depth.
  #
  # An introspection response with active: true AND an error string is a
  # DENIAL: the token is valid but the authorization service refused this
  # call (insufficient_scope, bound_exceeded, or an error code this SDK has
  # never heard of). The middleware returns 403 and never calls the app.
  #
  class Middleware
    # RFC 7235: the auth-scheme token is case-insensitive.
    # Match "bearer", "Bearer", "BEARER", etc. followed by the ag_at_ prefix.
    BEARER_AGENT_RE = /\Abearer ag_at_/i

    def initialize(app, scope_for: nil)
      @app = app
      @client = IntrospectionClient.new
      @config = AgentAdmit.configuration || Config.new
      @scope_for = scope_for
    end

    def call(env)
      auth = env["HTTP_AUTHORIZATION"] || ""

      if BEARER_AGENT_RE.match?(auth)
        # Strip the scheme prefix (case-insensitively) to get the bare token.
        token = auth.sub(/\Abearer /i, "")

        begin
          result = @client.verify(token,
                                  scope_used: resolve_scope(env),
                                  endpoint: env["PATH_INFO"],
                                  method: env["REQUEST_METHOD"])
          env["agentadmit.auth_type"] = "agent"
          env["agentadmit.user_id"] = result.user_id
          env["agentadmit.scopes"] = result.scopes
          env["agentadmit.connection_id"] = result.connection_id
          env["agentadmit.agent_label"] = result.agent_label
          env["agentadmit.presence"] = result.presence
        rescue ActiveDenialError => e
          # Token valid, call refused (active: true + error). Fail closed:
          # 403 with the denial's contract shape; the app never runs.
          return [403, { "Content-Type" => "application/json" },
            [e.denial_body.to_json]]
        rescue InvalidTokenError => e
          return [401, { "Content-Type" => "application/json" },
            [{ error: "invalid_token", error_description: e.message }.to_json]]
        rescue IntrospectionError => e
          return [502, { "Content-Type" => "application/json" },
            [{ error: "introspection_failed", error_description: e.message }.to_json]]
        end
      end

      @app.call(env)
    end

    private

    ##
    # The scope this request enforces, when the app declared one at mount
    # time. scope_for may be a Proc (env -> scope String or nil) or a
    # static String; nil (the default) omits scope_used from the verify body.
    #
    def resolve_scope(env)
      return @scope_for.call(env) if @scope_for.respond_to?(:call)

      @scope_for
    end
  end
end
