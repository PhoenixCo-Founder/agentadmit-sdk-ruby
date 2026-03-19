# frozen_string_literal: true

require_relative "agentadmit/version"
require_relative "agentadmit/config"
require_relative "agentadmit/introspection_client"
require_relative "agentadmit/middleware"
require_relative "agentadmit/scope_enforcement"
require_relative "agentadmit/railtie" if defined?(Rails)

module AgentAdmit
  class Error < StandardError; end
  class InvalidTokenError < Error; end
  class InsufficientScopeError < Error; end
  class IntrospectionError < Error; end

  class << self
    attr_accessor :configuration

    def configure
      self.configuration ||= Config.new
      yield(configuration) if block_given?
    end
  end
end
