# frozen_string_literal: true

module AgentAdmit
  ##
  # Controller concern for scope enforcement in Rails controllers.
  #
  # Usage:
  #   class OrdersController < ApplicationController
  #     include AgentAdmit::ScopeEnforcement
  #
  #     before_action -> { require_scope!("read:orders") }, only: [:index, :show]
  #     before_action -> { require_scope_if_agent!("create:orders") }, only: [:create]
  #     before_action -> { require_presence! }, only: [:destroy]
  #   end
  #
  module ScopeEnforcement
    extend ActiveSupport::Concern

    private

    ##
    # Enforce scope — agent MUST have this scope or gets 403.
    #
    def require_scope!(scope)
      unless request.env["agentadmit.auth_type"] == "agent"
        render json: { error: "invalid_token", error_description: "AgentAdmit token required" }, status: :unauthorized
        return
      end

      scopes = request.env["agentadmit.scopes"] || []
      unless scopes.include?(scope)
        render json: {
          error: "insufficient_scope",
          required_scope: scope,
          granted_scopes: scopes,
          message: "This action requires '#{scope}' scope."
        }, status: :forbidden
      end
    end

    ##
    # Enforce scope only for agent tokens. Regular users pass through.
    #
    def require_scope_if_agent!(scope)
      return unless request.env["agentadmit.auth_type"] == "agent"

      scopes = request.env["agentadmit.scopes"] || []
      unless scopes.include?(scope)
        render json: {
          error: "insufficient_scope",
          required_scope: scope,
          granted_scopes: scopes,
          message: "This action requires '#{scope}' scope."
        }, status: :forbidden
      end
    end

    ##
    # Enforce human-presence verification -- agent's connection MUST have been
    # authorized with a completed WebAuthn presence ceremony or gets 403.
    # Fail closed: connections from servers that predate the presence feature
    # (no presence block) are treated as not verified.
    #
    def require_presence!
      unless request.env["agentadmit.auth_type"] == "agent"
        render json: { error: "invalid_token", error_description: "AgentAdmit token required" }, status: :unauthorized
        return
      end

      presence = request.env["agentadmit.presence"]
      unless presence.is_a?(Hash) && presence["verified"] == true
        render json: {
          error: "presence_required",
          error_description: "This action requires a connection authorized with human presence verification."
        }, status: :forbidden
      end
    end

    ##
    # Get the current agent/user context.
    #
    def agentadmit_context
      {
        auth_type: request.env["agentadmit.auth_type"],
        user_id: request.env["agentadmit.user_id"],
        scopes: request.env["agentadmit.scopes"],
        connection_id: request.env["agentadmit.connection_id"],
        agent_label: request.env["agentadmit.agent_label"],
        presence: request.env["agentadmit.presence"],
      }
    end
  end
end
