# frozen_string_literal: true

module AgentAdmit
  class Railtie < Rails::Railtie
    initializer "agentadmit.middleware" do |app|
      app.middleware.use AgentAdmit::Middleware
      Rails.logger.info "[AgentAdmit] Middleware and scope enforcement active."
    end

    initializer "agentadmit.configure" do
      AgentAdmit.configure do |config|
        # Config loaded from environment variables by default
      end
    end

    # Include ScopeEnforcement into every ActionController so that
    # require_scope_if_agent! and require_scope! are available without
    # an explicit `include` in each controller.
    ActiveSupport.on_load(:action_controller) do
      include AgentAdmit::ScopeEnforcement
    end
  end
end
