# frozen_string_literal: true

module AgentAdmit
  ##
  # Rack middleware that intercepts requests with ag_at_ tokens
  # and validates them via introspection.
  #
  # Sets env variables for downstream use:
  #   env['agentadmit.auth_type']     — "agent" or nil
  #   env['agentadmit.user_id']       — validated user ID
  #   env['agentadmit.scopes']        — granted scopes array
  #   env['agentadmit.connection_id'] — connection identifier
  #   env['agentadmit.agent_label']   — agent display name
  #
  class Middleware
    def initialize(app)
      @app = app
      @client = IntrospectionClient.new
      @config = AgentAdmit.configuration || Config.new
    end

    def call(env)
      auth = env["HTTP_AUTHORIZATION"] || ""

      if auth.start_with?("Bearer #{@config.token_prefix_access}")
        token = auth.sub("Bearer ", "")

        begin
          result = @client.verify(token)
          env["agentadmit.auth_type"] = "agent"
          env["agentadmit.user_id"] = result.user_id
          env["agentadmit.scopes"] = result.scopes
          env["agentadmit.connection_id"] = result.connection_id
          env["agentadmit.agent_label"] = result.agent_label
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
  end
end
