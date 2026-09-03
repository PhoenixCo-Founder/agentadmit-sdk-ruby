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
  #   env['agentadmit.action_confirmation']
  #                                   -- {"action_session_id" =>, "consumed" => true}
  #                                      when a confirm-each-time confirmation
  #                                      was spent on THIS call; key absent
  #                                      otherwise
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
  # call (insufficient_scope, bound_exceeded, confirmation_required, or an
  # error code this SDK has never heard of). The middleware returns 403 and
  # never calls the app.
  #
  # Confirm-each-time (1.11.0). The agent's
  # X-AgentAdmit-Action-Attestation header is ALWAYS forwarded when present
  # -- with or without an action summary. Declare an action summary to make
  # a route confirm-each-time-ready: the middleware then also digests the
  # raw request body and sends the human-readable summary, so the hosted
  # ceremony (and the passkey signature) covers the exact payload:
  #
  #   use AgentAdmit::Middleware, scope_for: "write:payments",
  #       action_summary: ->(env) { "Pay #{params(env)['trainer']} $#{params(env)['amount']}" }
  #   # ... a static String, or a block, work too:
  #   use AgentAdmit::Middleware, scope_for: "write:payments" do |env|
  #     "Publish the draft post"
  #   end
  #
  class Middleware
    # RFC 7235: the auth-scheme token is case-insensitive.
    # Match "bearer", "Bearer", "BEARER", etc. followed by the ag_at_ prefix.
    BEARER_AGENT_RE = /\Abearer ag_at_/i

    ##
    # @param app [#call] the downstream Rack app
    # @param scope_for [Proc, String, nil] the scope this request enforces
    # @param action_summary [Proc, String, nil] confirm-each-time (1.11.0):
    #   the plain-language description of THIS action for the human ("Pay
    #   Alex $50"). A Proc (env -> String or nil) or a static String; a block
    #   is accepted as an alternative. Supplying one also turns on the raw
    #   request-body digest for this middleware. AgentAdmit does not verify
    #   the summary against the request; it proves what the human was shown.
    #
    def initialize(app, scope_for: nil, action_summary: nil, &action_summary_block)
      @app = app
      @client = IntrospectionClient.new
      @config = AgentAdmit.configuration || Config.new
      @scope_for = scope_for
      @action_summary = action_summary || action_summary_block
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
                                  method: env["REQUEST_METHOD"],
                                  action_attestation_id:
                                    IntrospectionClient.action_attestation_from_env(env),
                                  request_digest: resolve_request_digest(env),
                                  action_summary: resolve_action_summary(env))
          env["agentadmit.auth_type"] = "agent"
          env["agentadmit.user_id"] = result.user_id
          env["agentadmit.scopes"] = result.scopes
          env["agentadmit.connection_id"] = result.connection_id
          env["agentadmit.agent_label"] = result.agent_label
          env["agentadmit.presence"] = result.presence
          # Only set when the hosted service actually SPENT a confirmation on
          # this call; the key stays absent otherwise, so `env.key?` is a
          # truthful test.
          if result.action_confirmation
            env["agentadmit.action_confirmation"] = result.action_confirmation
          end
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

    ##
    # The plain-language action summary for this request, when the app
    # declared one at mount time. A Proc (env -> String or nil) or a static
    # String. A summary is telemetry for the human's confirmation page, never
    # an authorization input, so a callback that raises must not turn a
    # legitimate call into an error: it degrades to no summary.
    #
    def resolve_action_summary(env)
      return nil unless @action_summary

      summary = @action_summary.respond_to?(:call) ? @action_summary.call(env) : @action_summary
      summary.is_a?(String) ? summary : nil
    rescue StandardError
      nil
    end

    ##
    # `sha256:<hex>` over the RAW request body, computed only for a
    # middleware configured with an action summary (a confirm-each-time
    # route) -- the confirmation must cover the exact payload, not just the
    # route. The body is rewound afterwards so the downstream app still reads
    # it; a body this middleware cannot read simply yields no digest.
    #
    def resolve_request_digest(env)
      return nil unless @action_summary

      input = env["rack.input"]
      return nil unless input.respond_to?(:read)

      input.rewind if input.respond_to?(:rewind)
      raw = input.read
      input.rewind if input.respond_to?(:rewind)
      IntrospectionClient.request_digest_for(raw)
    rescue StandardError
      nil
    end
  end
end
