# frozen_string_literal: true

# Tests for the Consent Ledger surface: IntrospectionClient#check_consent
# strict response handling, and IntrospectionResult#consent_granted?
# fail-closed semantics.

require "minitest/autorun"
require "json"
require_relative "../lib/agentadmit"

# ---------------------------------------------------------------------------
# Helpers (mirrors StubHelpers in audit_fixes_test.rb; kept local so this
# file runs standalone)
# ---------------------------------------------------------------------------
module ConsentStubHelpers
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

  def verdict_body(overrides = {})
    {
      "granted" => true,
      "caller_class" => "in_app_ai",
      "scope_group" => nil,
      "source" => "default",
      "evaluated_at" => "2026-07-03T00:00:00Z"
    }.merge(overrides)
  end
end

# ---------------------------------------------------------------------------
# IntrospectionClient#check_consent
# ---------------------------------------------------------------------------
class CheckConsentTest < Minitest::Test
  include ConsentStubHelpers

  def test_granted_verdict_on_200
    resp = ConsentStubHelpers::FakeResponse.new("200", {}, JSON.generate(verdict_body))
    client = build_client(resp)
    verdict = client.check_consent(app_user_id: "user_1", caller_class: "in_app_ai")
    assert_equal true, verdict["granted"]
    assert_equal "in_app_ai", verdict["caller_class"]
  end

  def test_denied_verdict_on_200
    resp = ConsentStubHelpers::FakeResponse.new(
      "200", {}, JSON.generate(verdict_body("granted" => false))
    )
    client = build_client(resp)
    verdict = client.check_consent(app_user_id: "user_1", caller_class: "in_app_ai")
    assert_equal false, verdict["granted"]
  end

  def test_non_200_raises_introspection_error
    resp = ConsentStubHelpers::FakeResponse.new(
      "500", {}, JSON.generate("error" => "internal_error")
    )
    client = build_client(resp)
    err = assert_raises(AgentAdmit::IntrospectionError) do
      client.check_consent(app_user_id: "user_1", caller_class: "in_app_ai")
    end
    assert_match(/internal_error/, err.message)
  end

  def test_non_200_with_garbage_body_raises_introspection_error
    resp = ConsentStubHelpers::FakeResponse.new("503", {}, "upstream timeout")
    client = build_client(resp)
    err = assert_raises(AgentAdmit::IntrospectionError) do
      client.check_consent(app_user_id: "user_1", caller_class: "in_app_ai")
    end
    assert_match(/503/, err.message)
  end

  def test_malformed_json_200_body_raises_introspection_error
    # A 200 with a garbage body must not silently read as an empty verdict.
    resp = ConsentStubHelpers::FakeResponse.new("200", {}, "not json {{{")
    client = build_client(resp)
    err = assert_raises(AgentAdmit::IntrospectionError) do
      client.check_consent(app_user_id: "user_1", caller_class: "in_app_ai")
    end
    assert_match(/not valid JSON/, err.message)
  end

  def test_unknown_caller_class_raises_argument_error
    client = build_client(nil)
    assert_raises(ArgumentError) do
      client.check_consent(app_user_id: "user_1", caller_class: "robot_overlord")
    end
  end
end

# ---------------------------------------------------------------------------
# IntrospectionResult#consent_granted? -- fail-closed semantics
# ---------------------------------------------------------------------------
class ConsentGrantedStrictnessTest < Minitest::Test
  include ConsentStubHelpers

  def result_with_consent(consent)
    AgentAdmit::IntrospectionClient::IntrospectionResult.new(
      user_id: "user_1", connection_id: "conn_1",
      scopes: ["read:orders"], agent_label: "TestBot",
      sub: nil, role: nil, app_id: nil, jti: nil, exp: nil,
      consent: consent
    )
  end

  def test_explicit_true_is_granted
    assert result_with_consent("granted" => true).consent_granted?
  end

  def test_explicit_false_is_denied
    refute result_with_consent("granted" => false).consent_granted?
  end

  def test_string_true_is_denied
    # Non-boolean granted is malformed; fail closed.
    refute result_with_consent("granted" => "true").consent_granted?
  end

  def test_integer_one_is_denied
    refute result_with_consent("granted" => 1).consent_granted?
  end

  def test_missing_granted_key_is_denied
    refute result_with_consent("caller_class" => "external_agent").consent_granted?
  end

  def test_nil_consent_is_never_a_grant
    # The hosted service deliberately omits the block when its consent-store
    # read fails (designed degraded mode). Absence is NEVER a grant: this
    # predicate fails closed; CallerConsent resolves the authoritative
    # verdict through the Consent Ledger.
    refute result_with_consent(nil).consent_granted?
  end

  # -- via verify: consent block handling end to end --

  def test_verify_with_granted_consent
    body = ok_verify_body("consent" => { "granted" => true, "caller_class" => "external_agent" })
    resp = ConsentStubHelpers::FakeResponse.new("200", {}, JSON.generate(body))
    result = build_client(resp).verify("ag_at_dummy")
    assert result.consent_granted?
  end

  def test_verify_with_denied_consent
    body = ok_verify_body("consent" => { "granted" => false })
    resp = ConsentStubHelpers::FakeResponse.new("200", {}, JSON.generate(body))
    result = build_client(resp).verify("ag_at_dummy")
    refute result.consent_granted?
  end

  def test_verify_without_consent_block_fails_closed
    resp = ConsentStubHelpers::FakeResponse.new("200", {}, JSON.generate(ok_verify_body))
    result = build_client(resp).verify("ag_at_dummy")
    assert_nil result.consent
    refute result.consent_granted?, "absent verdict is never a grant"
  end

  def test_verify_with_malformed_consent_block_is_kept_and_denied
    body = ok_verify_body("consent" => { "granted" => "yes" })
    resp = ConsentStubHelpers::FakeResponse.new("200", {}, JSON.generate(body))
    result = build_client(resp).verify("ag_at_dummy")
    refute_nil result.consent
    refute result.consent_granted?
  end
end
