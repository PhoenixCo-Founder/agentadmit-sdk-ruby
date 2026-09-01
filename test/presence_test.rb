# frozen_string_literal: true

# Tests for the presence block (WebAuthn human-presence step-up, server
# Phase 2): verify must attach `presence` only when the platform returns a
# well-formed block (verified strictly boolean, like active), and
# IntrospectionResult#presence_verified? plus ScopeEnforcement's
# require_presence! must fail closed on absent/false/malformed presence.

require "minitest/autorun"
require "json"
require_relative "../lib/agentadmit"

# ---------------------------------------------------------------------------
# Helpers (mirrors ConsentStubHelpers in consent_test.rb; kept local so this
# file runs standalone)
# ---------------------------------------------------------------------------
module PresenceStubHelpers
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

  def ok_verify_body(overrides = {})
    {
      "active" => true,
      "user_id" => "user_1",
      "connection_id" => "conn_1",
      "scopes" => ["read:orders"],
      "agent_label" => "Test Agent"
    }.merge(overrides)
  end

  def presence_body(overrides = {})
    {
      "verified" => true,
      "method" => "webauthn",
      "uv" => true,
      "verified_at" => "2026-07-04T00:00:00Z"
    }.merge(overrides)
  end
end

# ---------------------------------------------------------------------------
# Verify: presence block handling end to end
# ---------------------------------------------------------------------------
class PresenceParsingTest < Minitest::Test
  include PresenceStubHelpers

  def verify_with(body)
    resp = PresenceStubHelpers::FakeResponse.new("200", {}, JSON.generate(body))
    build_client(resp).verify("ag_at_dummy")
  end

  def test_verified_presence_block_is_attached
    result = verify_with(ok_verify_body("presence" => presence_body))
    assert_equal presence_body, result.presence
    assert result.presence_verified?
  end

  def test_unverified_presence_block_is_attached_but_not_verified
    block = presence_body("verified" => false, "method" => nil, "uv" => nil, "verified_at" => nil)
    result = verify_with(ok_verify_body("presence" => block))
    assert_equal block, result.presence
    refute result.presence_verified?
  end

  def test_absent_presence_block_is_nil_and_not_verified
    # Older servers never send the block; fail closed.
    result = verify_with(ok_verify_body)
    assert_nil result.presence
    refute result.presence_verified?
  end

  def test_string_true_verified_is_treated_as_absent
    # verified must be strictly boolean, like active; coerced values drop the block.
    result = verify_with(ok_verify_body("presence" => presence_body("verified" => "true")))
    assert_nil result.presence
    refute result.presence_verified?
  end

  def test_integer_one_verified_is_treated_as_absent
    result = verify_with(ok_verify_body("presence" => presence_body("verified" => 1)))
    assert_nil result.presence
    refute result.presence_verified?
  end

  def test_missing_verified_key_is_treated_as_absent
    result = verify_with(ok_verify_body("presence" => { "method" => "webauthn" }))
    assert_nil result.presence
    refute result.presence_verified?
  end

  def test_non_hash_presence_is_treated_as_absent
    result = verify_with(ok_verify_body("presence" => "verified"))
    assert_nil result.presence
    refute result.presence_verified?
  end
end

# ---------------------------------------------------------------------------
# IntrospectionResult#presence_verified? -- fail-closed semantics
# ---------------------------------------------------------------------------
class PresenceVerifiedStrictnessTest < Minitest::Test
  include PresenceStubHelpers

  def result_with_presence(presence)
    AgentAdmit::IntrospectionClient::IntrospectionResult.new(
      user_id: "user_1", connection_id: "conn_1",
      scopes: ["read:orders"], agent_label: "TestBot",
      sub: nil, role: nil, app_id: nil, jti: nil, exp: nil,
      consent: nil, presence: presence
    )
  end

  def test_explicit_true_is_verified
    assert result_with_presence(presence_body).presence_verified?
  end

  def test_explicit_false_is_not_verified
    refute result_with_presence(presence_body("verified" => false)).presence_verified?
  end

  def test_nil_presence_is_not_verified
    refute result_with_presence(nil).presence_verified?
  end

  def test_string_true_is_not_verified
    refute result_with_presence("verified" => "true").presence_verified?
  end

  def test_non_hash_presence_is_not_verified
    refute result_with_presence("verified").presence_verified?
  end
end

# ---------------------------------------------------------------------------
# Middleware surfaces the presence block in the Rack env
# ---------------------------------------------------------------------------
class MiddlewarePresenceEnvTest < Minitest::Test
  include PresenceStubHelpers

  def setup
    AgentAdmit.configuration = stub_config
  end

  def teardown
    AgentAdmit.configuration = nil
  end

  def middleware_with_result(result)
    inner_app = ->(_env) { [200, {}, ["OK"]] }
    mw = AgentAdmit::Middleware.new(inner_app)
    fake_client = Object.new
    fake_client.define_singleton_method(:verify) { |_token, **| result }
    mw.instance_variable_set(:@client, fake_client)
    mw
  end

  def result_with_presence(presence)
    AgentAdmit::IntrospectionClient::IntrospectionResult.new(
      user_id: "user_1", connection_id: "conn_1",
      scopes: ["read:orders"], agent_label: "TestBot",
      sub: nil, role: nil, app_id: nil, jti: nil, exp: nil,
      consent: nil, presence: presence
    )
  end

  def test_presence_block_is_set_in_env
    mw = middleware_with_result(result_with_presence(presence_body))
    env = { "HTTP_AUTHORIZATION" => "Bearer ag_at_sometoken" }
    status, = mw.call(env)
    assert_equal 200, status
    assert_equal presence_body, env["agentadmit.presence"]
  end

  def test_absent_presence_is_nil_in_env
    mw = middleware_with_result(result_with_presence(nil))
    env = { "HTTP_AUTHORIZATION" => "Bearer ag_at_sometoken" }
    status, = mw.call(env)
    assert_equal 200, status
    assert_equal "agent", env["agentadmit.auth_type"]
    assert_nil env["agentadmit.presence"]
  end
end

# ---------------------------------------------------------------------------
# ScopeEnforcement#require_presence! -- 403/pass paths (lightweight stub,
# no full Rails; mirrors RailtieScopeEnforcementAutoIncludeTest)
# ---------------------------------------------------------------------------

# Minimal ActiveSupport::Concern compatible stub (same shape as the one in
# audit_fixes_test.rb; defined under a distinct name to avoid collisions).
module PresenceFakeActiveSupport
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

class RequirePresenceGuardTest < Minitest::Test
  include PresenceStubHelpers

  FakeRequest = Struct.new(:env)

  def controller_class
    ensure_scope_enforcement_loaded!

    klass = Class.new do
      attr_reader :rendered

      def initialize(env)
        @request = FakeRequest.new(env)
        @rendered = nil
      end

      def request
        @request
      end

      def render(json:, status:)
        @rendered = { json: json, status: status }
      end
    end
    klass.include(AgentAdmit::ScopeEnforcement)
    klass
  end

  def ensure_scope_enforcement_loaded!
    return if defined?(AgentAdmit::ScopeEnforcement)

    unless defined?(ActiveSupport)
      Object.const_set(:ActiveSupport, Module.new)
      ActiveSupport.const_set(:Concern, PresenceFakeActiveSupport::FakeConcern)
    end
    load File.expand_path("../../lib/agentadmit/scope_enforcement.rb", __FILE__)
  end

  def guard(env)
    controller = controller_class.new(env)
    controller.send(:require_presence!)
    controller.rendered
  end

  def agent_env(presence)
    {
      "agentadmit.auth_type" => "agent",
      "agentadmit.scopes" => ["read:orders"],
      "agentadmit.presence" => presence
    }
  end

  def test_missing_agent_token_renders_401_invalid_token
    rendered = guard({})
    refute_nil rendered
    assert_equal :unauthorized, rendered[:status]
    assert_equal "invalid_token", rendered[:json][:error]
  end

  def test_verified_presence_passes
    assert_nil guard(agent_env(presence_body))
  end

  def test_unverified_presence_renders_403_presence_required
    rendered = guard(agent_env(presence_body("verified" => false)))
    refute_nil rendered
    assert_equal :forbidden, rendered[:status]
    assert_equal "presence_required", rendered[:json][:error]
    assert_equal "This action requires a connection authorized with human presence verification.",
                 rendered[:json][:error_description]
  end

  def test_absent_presence_renders_403_fail_closed
    rendered = guard(agent_env(nil))
    refute_nil rendered
    assert_equal :forbidden, rendered[:status]
    assert_equal "presence_required", rendered[:json][:error]
  end

  def test_malformed_presence_renders_403_fail_closed
    rendered = guard(agent_env("verified" => "true"))
    refute_nil rendered
    assert_equal :forbidden, rendered[:status]
    assert_equal "presence_required", rendered[:json][:error]
  end
end
