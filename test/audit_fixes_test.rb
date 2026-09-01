# frozen_string_literal: true

# Tests for audit fixes: M4 (https enforcement), M5 (introspection validation),
# M7 (Bearer case-insensitivity), and H5 (ScopeEnforcement auto-inclusion).

require "minitest/autorun"
require "json"
require_relative "../lib/agentadmit"

# ---------------------------------------------------------------------------
# M4 -- HTTPS enforcement in Config
# ---------------------------------------------------------------------------
class ConfigHttpsValidationTest < Minitest::Test
  def fresh_config
    AgentAdmit::Config.new
  end

  def test_https_verify_url_accepted
    cfg = fresh_config
    cfg.verify_url = "https://api.agentadmit.com/api/v1/verify"
    assert_equal "https://api.agentadmit.com/api/v1/verify", cfg.verify_url
  end

  def test_https_api_url_accepted
    cfg = fresh_config
    cfg.api_url = "https://api.agentadmit.com"
    assert_equal "https://api.agentadmit.com", cfg.api_url
  end

  def test_http_on_localhost_accepted
    cfg = fresh_config
    cfg.verify_url = "http://localhost:3001/verify"
    assert_equal "http://localhost:3001/verify", cfg.verify_url
  end

  def test_http_on_127_0_0_1_accepted
    cfg = fresh_config
    cfg.api_url = "http://127.0.0.1:9000"
    assert_equal "http://127.0.0.1:9000", cfg.api_url
  end

  def test_http_on_ipv6_loopback_accepted
    cfg = fresh_config
    cfg.verify_url = "http://[::1]:4567/verify"
    assert_equal "http://[::1]:4567/verify", cfg.verify_url
  end

  def test_http_on_external_host_rejected
    cfg = fresh_config
    err = assert_raises(AgentAdmit::ConfigurationError) do
      cfg.verify_url = "http://example.com/verify"
    end
    assert_match(/https/, err.message)
    assert_match(/verify_url/, err.message)
  end

  def test_http_on_external_api_url_rejected
    cfg = fresh_config
    err = assert_raises(AgentAdmit::ConfigurationError) do
      cfg.api_url = "http://api.agentadmit.com"
    end
    assert_match(/https/, err.message)
    assert_match(/api_url/, err.message)
  end

  def test_default_verify_url_is_https
    cfg = AgentAdmit::Config.new
    assert cfg.verify_url.start_with?("https://"), "default verify_url must be https"
  end

  def test_default_api_url_is_https
    cfg = AgentAdmit::Config.new
    assert cfg.api_url.start_with?("https://"), "default api_url must be https"
  end
end

# ---------------------------------------------------------------------------
# Helpers shared by M5 and M7 tests
# ---------------------------------------------------------------------------
module StubHelpers
  def stub_config
    cfg = AgentAdmit::Config.new
    cfg.app_id = "app_test"
    cfg.api_key = "aa_test_key"
    cfg
  end

  FakeResponse = Struct.new(:code, :headers, :body) do
    def [](name)
      headers[name]
    end
  end

  def build_client(response)
    client = AgentAdmit::IntrospectionClient.new(stub_config)
    fake_http = Object.new
    fake_http.define_singleton_method(:request) { |_req| response }
    client.define_singleton_method(:build_http) { |_uri| fake_http }
    client
  end

  def ok_body(overrides = {})
    {
      "active" => true,
      "user_id" => "user_1",
      "connection_id" => "conn_1",
      "scopes" => ["read:orders"],
      "agent_label" => "Test Agent"
    }.merge(overrides)
  end

  def ok_response(overrides = {})
    FakeResponse.new("200", {}, JSON.generate(ok_body(overrides)))
  end
end

# ---------------------------------------------------------------------------
# M5 -- Strict introspection response validation
# ---------------------------------------------------------------------------
class IntrospectionResponseValidationTest < Minitest::Test
  include StubHelpers

  # -- active field --

  def test_active_true_passes
    client = build_client(ok_response)
    result = client.verify("ag_at_dummy")
    assert_equal "user_1", result.user_id
  end

  def test_active_false_raises_invalid_token
    resp = FakeResponse.new("200", {}, JSON.generate("active" => false, "error" => "token_expired"))
    client = build_client(resp)
    err = assert_raises(AgentAdmit::InvalidTokenError) { client.verify("ag_at_dummy") }
    assert_match(/token_expired/, err.message)
  end

  def test_active_string_true_raises_invalid_token
    # "true" as a string is not strictly true
    resp = FakeResponse.new("200", {}, JSON.generate(ok_body("active" => "true")))
    client = build_client(resp)
    assert_raises(AgentAdmit::InvalidTokenError) { client.verify("ag_at_dummy") }
  end

  def test_active_integer_1_raises_invalid_token
    resp = FakeResponse.new("200", {}, JSON.generate(ok_body("active" => 1)))
    client = build_client(resp)
    assert_raises(AgentAdmit::InvalidTokenError) { client.verify("ag_at_dummy") }
  end

  # -- HTTP status --

  def test_non_2xx_raises_introspection_error
    resp = FakeResponse.new("500", {}, "Internal Server Error")
    client = build_client(resp)
    assert_raises(AgentAdmit::IntrospectionError) { client.verify("ag_at_dummy") }
  end

  def test_401_raises_invalid_token_error
    resp = FakeResponse.new("401", {}, JSON.generate("error_description" => "bad key"))
    client = build_client(resp)
    assert_raises(AgentAdmit::InvalidTokenError) { client.verify("ag_at_dummy") }
  end

  def test_204_with_no_body_raises_introspection_error
    resp = FakeResponse.new("204", {}, "")
    client = build_client(resp)
    assert_raises(AgentAdmit::IntrospectionError) { client.verify("ag_at_dummy") }
  end

  # -- user_id field --

  def test_missing_user_id_raises_invalid_token
    body = ok_body
    body.delete("user_id")
    resp = FakeResponse.new("200", {}, JSON.generate(body))
    client = build_client(resp)
    assert_raises(AgentAdmit::InvalidTokenError) { client.verify("ag_at_dummy") }
  end

  def test_integer_user_id_raises_invalid_token
    resp = FakeResponse.new("200", {}, JSON.generate(ok_body("user_id" => 42)))
    client = build_client(resp)
    assert_raises(AgentAdmit::InvalidTokenError) { client.verify("ag_at_dummy") }
  end

  # -- connection_id field --

  def test_integer_connection_id_raises_invalid_token
    resp = FakeResponse.new("200", {}, JSON.generate(ok_body("connection_id" => 99)))
    client = build_client(resp)
    assert_raises(AgentAdmit::InvalidTokenError) { client.verify("ag_at_dummy") }
  end

  def test_nil_connection_id_passes
    resp = FakeResponse.new("200", {}, JSON.generate(ok_body("connection_id" => nil)))
    client = build_client(resp)
    result = client.verify("ag_at_dummy")
    assert_nil result.connection_id
  end

  # -- scopes field --

  def test_scopes_as_array_of_strings_passes
    client = build_client(ok_response("scopes" => ["read:orders", "write:orders"]))
    result = client.verify("ag_at_dummy")
    assert_equal ["read:orders", "write:orders"], result.scopes
  end

  def test_scopes_as_string_raises_invalid_token
    resp = FakeResponse.new("200", {}, JSON.generate(ok_body("scopes" => "read:orders")))
    client = build_client(resp)
    assert_raises(AgentAdmit::InvalidTokenError) { client.verify("ag_at_dummy") }
  end

  def test_scopes_as_array_of_integers_raises_invalid_token
    resp = FakeResponse.new("200", {}, JSON.generate(ok_body("scopes" => [1, 2])))
    client = build_client(resp)
    assert_raises(AgentAdmit::InvalidTokenError) { client.verify("ag_at_dummy") }
  end

  def test_missing_scopes_field_returns_empty_array
    body = ok_body
    body.delete("scopes")
    resp = FakeResponse.new("200", {}, JSON.generate(body))
    client = build_client(resp)
    result = client.verify("ag_at_dummy")
    assert_equal [], result.scopes
  end
end

# ---------------------------------------------------------------------------
# M7 -- Bearer scheme case-insensitivity in Middleware
# ---------------------------------------------------------------------------

# Reusable stub result for middleware tests -- keyword_init struct so
# we build it via a plain Hash to avoid keyword argument issues.
STUB_RESULT = AgentAdmit::IntrospectionClient::IntrospectionResult.new(
  user_id: "user_1", connection_id: "conn_1",
  scopes: ["read:orders"], agent_label: "TestBot",
  sub: nil, role: nil, app_id: nil, jti: nil, exp: nil
)

class MiddlewareBearerCaseTest < Minitest::Test
  include StubHelpers

  def setup
    AgentAdmit.configuration = stub_config
  end

  def teardown
    AgentAdmit.configuration = nil
  end

  def middleware_with_ok_client
    inner_app = ->(env) { [200, {}, ["OK"]] }
    mw = AgentAdmit::Middleware.new(inner_app)
    fake_client = Object.new
    fake_client.define_singleton_method(:verify) { |_token, **| STUB_RESULT }
    mw.instance_variable_set(:@client, fake_client)
    mw
  end

  def test_bearer_uppercase_is_recognized
    mw = middleware_with_ok_client
    env = { "HTTP_AUTHORIZATION" => "BEARER ag_at_sometoken" }
    status, = mw.call(env)
    assert_equal 200, status
    assert_equal "agent", env["agentadmit.auth_type"]
  end

  def test_bearer_mixed_case_is_recognized
    mw = middleware_with_ok_client
    env = { "HTTP_AUTHORIZATION" => "BeArEr ag_at_sometoken" }
    status, = mw.call(env)
    assert_equal 200, status
    assert_equal "agent", env["agentadmit.auth_type"]
  end

  def test_bearer_lowercase_is_recognized
    mw = middleware_with_ok_client
    env = { "HTTP_AUTHORIZATION" => "bearer ag_at_sometoken" }
    status, = mw.call(env)
    assert_equal 200, status
    assert_equal "agent", env["agentadmit.auth_type"]
  end

  def test_standard_bearer_is_recognized
    mw = middleware_with_ok_client
    env = { "HTTP_AUTHORIZATION" => "Bearer ag_at_sometoken" }
    status, = mw.call(env)
    assert_equal 200, status
    assert_equal "agent", env["agentadmit.auth_type"]
  end

  def test_non_agent_token_is_ignored
    inner_app = ->(env) { [200, {}, ["passthrough"]] }
    mw = AgentAdmit::Middleware.new(inner_app)
    env = { "HTTP_AUTHORIZATION" => "Bearer some_other_token" }
    status, _, body = mw.call(env)
    assert_equal 200, status
    assert_equal ["passthrough"], body
    assert_nil env["agentadmit.auth_type"]
  end
end

# ---------------------------------------------------------------------------
# H5 -- ScopeEnforcement auto-inclusion (lightweight stub, no full Rails)
# ---------------------------------------------------------------------------

# Minimal ActiveSupport::Concern compatible stub.
# Defined at top-level (not inside a block) to satisfy Ruby 4 syntax rules.
module FakeActiveSupport
  module FakeConcern
    def self.extended(base)
      base.instance_variable_set(:@_included_block, nil)
      base.extend(ConcernClassMethods)
    end

    module ConcernClassMethods
      def included(base = nil, &block)
        if block
          @_included_block = block
        elsif base && @_included_block
          base.class_eval(&@_included_block)
        end
      end
    end
  end
end

class RailtieScopeEnforcementAutoIncludeTest < Minitest::Test
  # Verify that AgentAdmit::ScopeEnforcement is includable into a plain class
  # and that doing so makes the concern methods available as instance methods.
  #
  # This simulates what the Railtie does via ActiveSupport.on_load(:action_controller).
  def test_scope_enforcement_concern_is_includable_in_a_plain_class
    # Load ScopeEnforcement if it wasn't loaded (it's guarded by defined?(ActiveSupport)).
    unless defined?(AgentAdmit::ScopeEnforcement)
      unless defined?(ActiveSupport)
        # Inject our stub so the `require_relative` inside agentadmit.rb can use it.
        Object.const_set(:ActiveSupport, Module.new)
        ActiveSupport.const_set(:Concern, FakeActiveSupport::FakeConcern)
        @stub_active_support = true
      end
      load File.expand_path("../../lib/agentadmit/scope_enforcement.rb", __FILE__)
    end

    fake_controller_base = Class.new

    # This is exactly what the Railtie does on :action_controller load.
    fake_controller_base.include(AgentAdmit::ScopeEnforcement)

    # The concern's methods are private (before_action helpers).
    # Check both public and private visibility.
    def_check = ->(m) do
      fake_controller_base.method_defined?(m) ||
        fake_controller_base.private_method_defined?(m)
    end

    assert def_check.call(:require_scope_if_agent!),
      "require_scope_if_agent! must be defined after including ScopeEnforcement"
    assert def_check.call(:require_scope!),
      "require_scope! must be defined after including ScopeEnforcement"
    assert def_check.call(:agentadmit_context),
      "agentadmit_context must be defined after including ScopeEnforcement"
  ensure
    if @stub_active_support
      Object.send(:remove_const, :ActiveSupport) rescue nil
    end
  end
end
