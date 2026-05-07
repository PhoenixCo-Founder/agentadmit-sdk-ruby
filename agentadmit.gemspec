# frozen_string_literal: true

require_relative "lib/agentadmit/version"

Gem::Specification.new do |spec|
  spec.name = "agentadmit"
  spec.version = AgentAdmit::VERSION
  spec.authors = ["Christopher Emerson"]
  spec.summary = "AgentAdmit SDK for Ruby on Rails — User-mediated AI agent authorization"
  spec.description = "Integrate AgentAdmit into your Rails app. Mandatory introspection, scope enforcement, and secure AI agent connections."
  spec.homepage = "https://agentadmit.com/docs"
  spec.license = "Nonstandard"
  spec.required_ruby_version = ">= 3.1.0"

  spec.files = Dir["lib/**/*", "LICENSE", "README.md"]
  spec.require_paths = ["lib"]

  spec.add_dependency "json"
end
