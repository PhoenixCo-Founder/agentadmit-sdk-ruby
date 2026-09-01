# frozen_string_literal: true

# Tests for SDK 1.10.0: per-call verification telemetry + active-error
# fail-closed (semantic matrix sections 1-6).
#
#  - The introspection POST body gains optional scope_used / endpoint /
#    method -- sent whenever known, OMITTED when not (never null/empty).
#    endpoint is path-only (query stripped -- queries can carry PII) and
#    truncated to 500 chars; method is uppercased and capped at 20.
#  - An introspection response with active: true AND a string error field is
#    a DENIAL, never a pass-through: insufficient_scope -> 403 step-up shape,
#    bound_exceeded -> 403 with hosted fields verbatim, any unknown error
#    string -> 403 generic fail-closed. The downstream app never runs.

require "minitest/autorun"
require "json"
require_relative "../lib/agentadmit"

module TelemetryStubHelpers
  FakeResponse = Struct.new(:code, :headers, :body) do
    def [](name)
      headers[name]
    end
  end

  def stub_config
    cfg = AgentAdmit::Config.new
    cfg.app_id = "app_test"
    cfg.api_key = "aa_test_key"
    cfg
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

  def ok_response(body)
    FakeResponse.new("200", {}, JSON.generate(body))
  end

  # A real IntrospectionClient whose HTTP layer replays canned responses and
  # records every Net::HTTP request (mirrors the build_http stub pattern).
  def capture_client(response, requests)
    client = AgentAdmit::IntrospectionClient.new(stub_config)
    queue = response.is_a?(Array) ? response.dup : nil
    fake_http = Object.new
    fake_http.define_singleton_method(:request) do |req|
      requests.push(req)
      queue ? queue.shift : response
    end
    client.define_singleton_method(:build_http) { |_uri| fake_http }
    client
  end

  def sent_body(requests, index = 0)
    JSON.parse(requests.fetch(index).body)
  end

  def parse(body_parts)
    JSON.parse(body_parts.first)
  end
end

# ---------------------------------------------------------------------------
# Section 1: verify body -- direct client calls
# ---------------------------------------------------------------------------
class VerifyBodyTelemetryTest < Minitest::Test
  include TelemetryStubHelpers

  def test_body_carries_all_three_fields_when_known
    requests = []
    capture_client(ok_response(ok_verify_body), requests)
      .verify("ag_at_dummy", scope_used: "read:orders", endpoint: "/orders", method: "GET")

    body = sent_body(requests)
    assert_equal "ag_at_dummy", body["token"]
    assert_equal "read:orders", body["scope_used"]
    assert_equal "/orders", body["endpoint"]
    assert_equal "GET", body["method"]
  end

  def test_bare_verify_sends_token_only_backward_compatible
    requests = []
    capture_client(ok_response(ok_verify_body), requests).verify("ag_at_dummy")

    assert_equal({ "token" => "ag_at_dummy" }, sent_body(requests))
  end

  def test_unknown_fields_are_omitted_never_null
    requests = []
    capture_client(ok_response(ok_verify_body), requests)
      .verify("ag_at_dummy", endpoint: "/orders", method: "GET")

    body = sent_body(requests)
    refute body.key?("scope_used"), "unknown scope must be omitted, not null"
    assert_equal "/orders", body["endpoint"]
    assert_equal "GET", body["method"]
  end

  def test_empty_strings_are_omitted
    requests = []
    capture_client(ok_response(ok_verify_body), requests)
      .verify("ag_at_dummy", scope_used: "", endpoint: "", method: "")

    assert_equal({ "token" => "ag_at_dummy" }, sent_body(requests))
  end

  def test_endpoint_query_string_is_stripped
    requests = []
    capture_client(ok_response(ok_verify_body), requests)
      .verify("ag_at_dummy", endpoint: "/orders/123?email=pii@example.com&q=secret", method: "GET")

    assert_equal "/orders/123", sent_body(requests)["endpoint"]
  end

  def test_endpoint_truncated_to_500_chars
    requests = []
    long_path = "/#{'a' * 700}"
    capture_client(ok_response(ok_verify_body), requests)
      .verify("ag_at_dummy", endpoint: long_path, method: "GET")

    sent = sent_body(requests)["endpoint"]
    assert_equal 500, sent.length
    assert_equal long_path[0, 500], sent
  end

  def test_query_stripped_before_truncation
    requests = []
    capture_client(ok_response(ok_verify_body), requests)
      .verify("ag_at_dummy", endpoint: "/short?#{'q' * 600}", method: "GET")

    assert_equal "/short", sent_body(requests)["endpoint"]
  end

  def test_method_is_uppercased_and_capped_at_20
    requests = []
    capture_client(ok_response(ok_verify_body), requests)
      .verify("ag_at_dummy", endpoint: "/orders", method: "get")
    capture_client(ok_response(ok_verify_body), requests)
      .verify("ag_at_dummy", endpoint: "/orders", method: "x" * 30)

    assert_equal "GET", sent_body(requests, 0)["method"]
    assert_equal "X" * 20, sent_body(requests, 1)["method"]
  end

  def test_active_without_error_is_unchanged
    # Section 5: no behavior change for active responses without error.
    requests = []
    result = capture_client(ok_response(ok_verify_body), requests)
             .verify("ag_at_dummy", scope_used: "read:orders", endpoint: "/orders", method: "GET")

    assert_equal "user_1", result.user_id
    assert_equal ["read:orders"], result.scopes
  end
end

# ---------------------------------------------------------------------------
# Section 4: active-error fail-closed -- client raises typed denials
# ---------------------------------------------------------------------------
class ActiveErrorDenialClientTest < Minitest::Test
  include TelemetryStubHelpers

  def denial_from(body, **verify_opts)
    requests = []
    capture_client(ok_response(body), requests).verify("ag_at_dummy", **verify_opts)
  end

  def test_insufficient_scope_raises_with_step_up_fields
    body = ok_verify_body("error" => "insufficient_scope",
                          "error_description" => "Scope not granted",
                          "scopes" => ["read:orders"])
    error = assert_raises(AgentAdmit::InsufficientScopeError) do
      denial_from(body, scope_used: "write:orders")
    end

    assert_kind_of AgentAdmit::ActiveDenialError, error
    assert_equal "insufficient_scope", error.code
    assert_equal "write:orders", error.required_scope, "falls back to the scope this call enforced"
    assert_equal ["read:orders"], error.granted_scopes
  end

  def test_insufficient_scope_prefers_hosted_required_scope
    body = ok_verify_body("error" => "insufficient_scope",
                          "required_scope" => "write:orders",
                          "granted_scopes" => ["read:orders"])
    error = assert_raises(AgentAdmit::InsufficientScopeError) { denial_from(body) }

    assert_equal "write:orders", error.required_scope
    assert_equal ["read:orders"], error.granted_scopes
  end

  def test_bound_exceeded_raises_with_hosted_fields
    body = ok_verify_body("error" => "bound_exceeded",
                          "error_description" => "Per-connection call bound exhausted",
                          "bound" => { "calls" => 100, "used" => 100 },
                          "renewal" => "2026-09-02T00:00:00Z")
    error = assert_raises(AgentAdmit::BoundExceededError) { denial_from(body) }

    assert_equal "bound_exceeded", error.code
    assert_equal "Per-connection call bound exhausted", error.message
    expected = { "error" => "bound_exceeded",
                 "error_description" => "Per-connection call bound exhausted",
                 "bound" => { "calls" => 100, "used" => 100 },
                 "renewal" => "2026-09-02T00:00:00Z" }
    assert_equal expected, error.denial_body
  end

  def test_unknown_active_error_string_raises_generic_denial
    body = ok_verify_body("error" => "quota_frozen")
    error = assert_raises(AgentAdmit::ActiveDenialError) { denial_from(body) }

    assert_equal "quota_frozen", error.code
    assert_equal({ "error" => "quota_frozen",
                   "error_description" => "Call refused by the authorization service." },
                 error.denial_body)
  end

  def test_inactive_with_error_still_raises_invalid_token
    # active: false keeps its existing mapping -- the denial path is only
    # for active responses.
    body = { "active" => false, "error" => "token_revoked" }
    error = assert_raises(AgentAdmit::InvalidTokenError) { denial_from(body) }
    assert_equal "token_revoked", error.code
  end
end

# ---------------------------------------------------------------------------
# Sections 1+2+4: Rack Middleware -- telemetry out, denials to 403
# ---------------------------------------------------------------------------
class MiddlewareTelemetryTest < Minitest::Test
  include TelemetryStubHelpers

  def setup
    AgentAdmit.configuration = stub_config
  end

  def teardown
    AgentAdmit.configuration = nil
  end

  # Middleware over a real client with a stubbed HTTP layer; records verify
  # requests and whether the downstream app ran.
  def build(response, requests, scope_for: nil)
    app_calls = []
    inner_app = lambda do |env|
      app_calls << env
      [200, { "Content-Type" => "application/json" }, [{ ok: true }.to_json]]
    end
    mw = AgentAdmit::Middleware.new(inner_app, scope_for: scope_for)
    mw.instance_variable_set(:@client, capture_client(response, requests))
    [mw, app_calls]
  end

  def agent_env(overrides = {})
    { "HTTP_AUTHORIZATION" => "Bearer ag_at_dummy",
      "PATH_INFO" => "/orders/42",
      "REQUEST_METHOD" => "GET" }.merge(overrides)
  end

  def test_scope_enforcing_middleware_sends_all_three_fields
    requests = []
    mw, = build(ok_response(ok_verify_body), requests,
                scope_for: ->(env) { env["PATH_INFO"].start_with?("/orders") ? "read:orders" : nil })
    status, = mw.call(agent_env)

    assert_equal 200, status
    body = sent_body(requests)
    assert_equal "read:orders", body["scope_used"]
    assert_equal "/orders/42", body["endpoint"]
    assert_equal "GET", body["method"]
  end

  def test_static_scope_for_string_is_sent
    requests = []
    mw, = build(ok_response(ok_verify_body), requests, scope_for: "read:orders")
    mw.call(agent_env)

    assert_equal "read:orders", sent_body(requests)["scope_used"]
  end

  def test_without_scope_omits_scope_used_but_sends_endpoint_and_method
    requests = []
    mw, = build(ok_response(ok_verify_body), requests)
    status, = mw.call(agent_env)

    assert_equal 200, status
    body = sent_body(requests)
    refute body.key?("scope_used"), "no scope known -> field omitted, not null"
    assert_equal "/orders/42", body["endpoint"]
    assert_equal "GET", body["method"]
  end

  def test_bound_exceeded_is_403_and_app_not_called
    requests = []
    body = ok_verify_body("error" => "bound_exceeded",
                          "error_description" => "Per-connection call bound exhausted",
                          "bound" => { "calls" => 100, "used" => 100 },
                          "renewal" => "2026-09-02T00:00:00Z")
    mw, app_calls = build(ok_response(body), requests)
    status, headers, resp = mw.call(agent_env)

    assert_equal 403, status
    assert_equal "application/json", headers["Content-Type"]
    parsed = parse(resp)
    assert_equal "bound_exceeded", parsed["error"]
    assert_equal "Per-connection call bound exhausted", parsed["error_description"]
    assert_equal({ "calls" => 100, "used" => 100 }, parsed["bound"])
    assert_equal "2026-09-02T00:00:00Z", parsed["renewal"]
    assert_empty app_calls, "active-error is a DENIAL; the app must not run"
  end

  def test_insufficient_scope_is_403_step_up_shape
    requests = []
    body = ok_verify_body("error" => "insufficient_scope", "scopes" => ["read:orders"])
    mw, app_calls = build(ok_response(body), requests, scope_for: "write:orders")
    status, _headers, resp = mw.call(agent_env)

    assert_equal 403, status
    parsed = parse(resp)
    assert_equal "insufficient_scope", parsed["error"]
    assert_equal "write:orders", parsed["required_scope"]
    assert_equal ["read:orders"], parsed["granted_scopes"]
    assert_empty app_calls
  end

  def test_unknown_active_error_is_403_fail_closed
    requests = []
    mw, app_calls = build(ok_response(ok_verify_body("error" => "quota_frozen")), requests)
    status, _headers, resp = mw.call(agent_env)

    assert_equal 403, status
    parsed = parse(resp)
    assert_equal "quota_frozen", parsed["error"]
    assert_equal "Call refused by the authorization service.", parsed["error_description"]
    assert_empty app_calls, "unknown error strings fail closed; the app must not run"
  end

  def test_invalid_token_is_still_401
    requests = []
    mw, app_calls = build(ok_response("active" => false, "error" => "token_revoked"), requests)
    status, = mw.call(agent_env)

    assert_equal 401, status
    assert_empty app_calls
  end
end

# ---------------------------------------------------------------------------
# CallerConsent: telemetry from the scope-enforcing middleware + denials
# ---------------------------------------------------------------------------
class CallerConsentTelemetryTest < Minitest::Test
  include TelemetryStubHelpers

  def build(response, requests, **opts)
    app_calls = []
    inner_app = lambda do |env|
      app_calls << env
      [200, { "Content-Type" => "application/json" }, [{ ok: true }.to_json]]
    end
    mw = AgentAdmit::CallerConsent.new(inner_app, **opts)
    mw.instance_variable_set(:@client, capture_client(response, requests))
    [mw, app_calls]
  end

  def agent_env
    { "HTTP_AUTHORIZATION" => "Bearer ag_at_dummy",
      "PATH_INFO" => "/orders/42",
      "REQUEST_METHOD" => "GET" }
  end

  def consented_body(overrides = {})
    ok_verify_body(
      "consent" => { "caller_class" => "external_agent", "granted" => true,
                     "source" => "app_default", "evaluated_at" => "x" }
    ).merge(overrides)
  end

  def test_required_scope_flows_with_consent_first_ordering
    requests = []
    mw, = build(ok_response(consented_body), requests, required_scope: "read:orders")
    status, = mw.call(agent_env)

    assert_equal 200, status
    body = sent_body(requests)
    assert_equal "read:orders", body["scope_used"]
    assert_equal "/orders/42", body["endpoint"]
    assert_equal "GET", body["method"]
    assert_equal true, body["consent_first"]
  end

  def test_local_step_up_still_enforced_after_consent
    requests = []
    mw, app_calls = build(ok_response(consented_body), requests, required_scope: "write:orders")
    status, _headers, resp = mw.call(agent_env)

    assert_equal 403, status
    parsed = parse(resp)
    assert_equal "insufficient_scope", parsed["error"]
    assert_equal "write:orders", parsed["required_scope"]
    assert_empty app_calls
  end

  def test_no_required_scope_omits_scope_used
    requests = []
    mw, = build(ok_response(consented_body), requests)
    mw.call(agent_env)

    body = sent_body(requests)
    refute body.key?("scope_used")
    assert_equal "/orders/42", body["endpoint"]
    assert_equal "GET", body["method"]
    assert_equal true, body["consent_first"]
  end

  def test_hosted_scope_refusal_after_consent_fails_closed
    # consent_first guarantees the hosted service can return this shape only
    # after consent has been granted.
    requests = []
    body = { "active" => true,
             "error" => "insufficient_scope",
             "error_description" => 'Scope "write:orders" was not granted for this connection.',
             "granted_scopes" => ["read:orders"] }
    mw, app_calls = build(ok_response(body), requests, required_scope: "write:orders")
    status, _headers, resp = mw.call(agent_env)

    assert_equal 403, status
    parsed = parse(resp)
    assert_equal "insufficient_scope", parsed["error"]
    refute parsed.key?("granted_scopes"), "guard must not leak granted scopes"
    refute parsed.key?("required_scope"), "guard must not leak required scope"
    assert_empty app_calls
  end

  def test_bound_exceeded_is_403_and_app_not_called
    requests = []
    body = consented_body("error" => "bound_exceeded",
                          "error_description" => "Per-connection call bound exhausted")
    mw, app_calls = build(ok_response(body), requests, required_scope: "read:orders")
    status, _headers, resp = mw.call(agent_env)

    assert_equal 403, status
    assert_equal "bound_exceeded", parse(resp)["error"]
    assert_empty app_calls
  end

  def test_unknown_active_error_is_403_fail_closed
    requests = []
    mw, app_calls = build(ok_response(consented_body("error" => "quota_frozen")), requests)
    status, _headers, resp = mw.call(agent_env)

    assert_equal 403, status
    parsed = parse(resp)
    assert_equal "quota_frozen", parsed["error"]
    assert_equal "Call refused by the authorization service.", parsed["error_description"]
    assert_empty app_calls
  end
end
