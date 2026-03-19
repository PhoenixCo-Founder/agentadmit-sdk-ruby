# frozen_string_literal: true

module AgentAdmit
  class Railtie < Rails::Railtie
    initializer "agentadmit.middleware" do |app|
      app.middleware.use AgentAdmit::Middleware
    end

    initializer "agentadmit.configure" do
      AgentAdmit.configure do |config|
        # Config loaded from environment variables by default
      end
    end
  end
end
