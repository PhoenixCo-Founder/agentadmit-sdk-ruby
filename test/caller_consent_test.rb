# frozen_string_literal: true

# Tests for the CallerConsent Rack middleware: classify the caller from
# credential structure before any consent check; route each class to its OWN
# isolated path; fail closed on a denied verdict or an unreachable ledger;
# and never let one class inherit another's decision.

require "minitest/autorun"
require "json"
require_relative "../lib/agentadmit"

module CallerConsentStubHelpers
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

  # Build a middleware whose IntrospectionClient talks to a fake HTTP layer.
  # ledger_calls counts fake round-trips so tests can prove the human path
  # never asks the ledger. response may be an Array: each round-trip consumes
  # the next entry (a nil entry raises, simulating a network failure), which
  # lets one test serve introspection and the /consent/check fallback
  # different responses. requests records every Net::HTTP request so tests
  # can assert what was sent where.
  def build_middleware(app, response, ledger_calls: nil, requests: nil, **opts)
    mw = AgentAdmit::CallerConsent.new(app, **opts)
    client = AgentAdmit::IntrospectionClient.new(stub_config)
    queue = response.is_a?(Array) ? response.dup : nil
    fake_http = Object.new
    fake_http.define_singleton_method(:request) do |req|
      ledger_calls&.call
      requests&.push(req)
      current = queue ? queue.shift : response
      raise StandardError, "network down" if current.nil?

      current
    end
    client.define_singleton_method(:build_http) { |_uri| fake_http }
    mw.instance_variable_set(:@client, client)
    mw
  end

  def ok_app
    ->(env) { [200, { "Content-Type" => "application/json" }, [{ ok: true }.to_json]] }
  end

  def ok_verify_body(overrides = {})
    {
      "active" => true,
      "user_id" => "user_1",
      "connection_id" => "conn_1",
      "scopes" => ["read:things"],
      "agent_label" => "Test Agent",
      "consent" => { "caller_class" => "external_agent", "granted" => true,
                     "source" => "app_default", "evaluated_at" => "x" }
    }.merge(overrides)
  end

  # Introspection response WITHOUT a consent verdict -- the hosted service
  # omits the block when its consent-store read fails (designed degraded
  # mode); the SDK must resolve the verdict through the Consent Ledger.
  def verify_body_no_verdict
    ok_verify_body.tap { |h| h.delete("consent") }
  end

  def ledger_verdict(granted)
    { "caller_class" => "external_agent", "granted" => granted,
      "source" => granted ? "app_default" : "setting", "evaluated_at" => "x" }
  end

  def ok_response(body)
    FakeResponse.new("200", {}, JSON.generate(body))
  end

  def agent_env
    { "HTTP_AUTHORIZATION" => "Bearer ag_at_dummy" }
  end

  def human_env
    { "HTTP_AUTHORIZATION" => "Bearer session_jwt" }
  end

  def parse(body_parts)
    JSON.parse(body_parts.first)
  end
end

class CallerConsentClassifyTest < Minitest::Test
  include CallerConsentStubHelpers

  def test_agent_token_is_external_agent
    mw = build_middleware(ok_app, nil)
    assert_equal "external_agent", mw.classify_caller(agent_env)
  end

  def test_non_agent_defaults_to_human
    mw = build_middleware(ok_app, nil)
    assert_equal "human_session", mw.classify_caller(human_env)
  end

  def test_honors_non_agent_classifier
    mw = build_middleware(ok_app, nil,
      classify_non_agent: ->(env) { env["HTTP_X_INTERNAL_AI"] == "secret" ? "in_app_ai" : "human_session" })
    assert_equal "in_app_ai", mw.classify_caller("HTTP_X_INTERNAL_AI" => "secret")
  end
end

class CallerConsentExternalAgentTest < Minitest::Test
  include CallerConsentStubHelpers

  def test_allows_with_required_scope
    env = agent_env
    status, _h, _b = build_middleware(ok_app, ok_response(ok_verify_body), required_scope: "read:things").call(env)

    assert_equal 200, status
    assert_equal "agent", env["agentadmit.auth_type"]
    assert_equal "external_agent", env["agentadmit.caller_class"]
  end

  def test_denies_missing_scope
    status, _h, body = build_middleware(ok_app, ok_response(ok_verify_body), required_scope: "write:things").call(agent_env)

    assert_equal 403, status
    assert_equal "insufficient_scope", parse(body)["error"]
    assert_equal "write:things", parse(body)["required_scope"]
  end

  def test_denies_when_consent_denied
    body = ok_verify_body("consent" => { "caller_class" => "external_agent", "granted" => false, "source" => "setting" })
    status, _h, resp = build_middleware(ok_app, ok_response(body)).call(agent_env)

    assert_equal 403, status
    assert_equal "consent_not_granted", parse(resp)["error"]
  end

  # Consent BEFORE scope (Patent FIG. 3 stage order): a caller whose class the
  # owner denied must not learn scope state -- no insufficient_scope, no
  # granted_scopes, even when the scope is ALSO missing.
  def test_denied_consent_wins_over_missing_scope
    body = ok_verify_body("consent" => { "caller_class" => "external_agent", "granted" => false, "source" => "setting" })
    status, _h, resp = build_middleware(ok_app, ok_response(body), required_scope: "write:things").call(agent_env)

    assert_equal 403, status
    parsed = parse(resp)
    assert_equal "consent_not_granted", parsed["error"]
    refute parsed.key?("granted_scopes"), "denied class must not learn scope state"
    refute parsed.key?("required_scope")
  end

  def test_absent_verdict_resolved_via_ledger_allow
    requests = []
    env = agent_env
    responses = [ok_response(verify_body_no_verdict), ok_response(ledger_verdict(true))]
    status, _h, _b = build_middleware(ok_app, responses, requests: requests, scope_group: "reports").call(env)

    assert_equal 200, status
    assert_equal 2, requests.length, "introspection + ledger fallback"
    assert_match %r{/consent/check\z}, requests[1].path
    ledger_body = JSON.parse(requests[1].body)
    assert_equal "external_agent", ledger_body["caller_class"]
    assert_equal "reports", ledger_body["scope_group"]
    assert_equal "user_1", ledger_body["app_user_id"], "owner comes from the introspection result"
    assert_equal true, env["agentadmit.consent"]["granted"], "resolved verdict lands in the env"
  end

  def test_absent_verdict_resolved_via_ledger_deny
    responses = [ok_response(verify_body_no_verdict), ok_response(ledger_verdict(false))]
    status, _h, body = build_middleware(ok_app, responses).call(agent_env)

    assert_equal 403, status
    assert_equal "consent_not_granted", parse(body)["error"]
  end

  def test_absent_verdict_with_ledger_error_fails_closed
    responses = [ok_response(verify_body_no_verdict), nil] # ledger round-trip raises
    status, _h, body = build_middleware(ok_app, responses).call(agent_env)

    assert_equal 503, status
    assert_equal "consent_unavailable", parse(body)["error"]
  end

  def test_malformed_verdict_resolved_via_ledger
    # A present block with a non-boolean granted is malformed -- never a
    # grant; the ledger holds the authoritative answer.
    body = ok_verify_body("consent" => { "caller_class" => "external_agent", "granted" => "yes" })
    requests = []
    responses = [ok_response(body), ok_response(ledger_verdict(true))]
    status, _h, _b = build_middleware(ok_app, responses, requests: requests).call(agent_env)

    assert_equal 200, status
    assert_equal 2, requests.length, "malformed verdict must be re-resolved via the ledger"
    assert_match %r{/consent/check\z}, requests[1].path
  end

  def test_rejects_invalid_token
    status, _h, _b = build_middleware(ok_app, ok_response("active" => false, "error" => "invalid_token")).call(agent_env)
    assert_equal 401, status
  end
end

class CallerConsentInAppAiTest < Minitest::Test
  include CallerConsentStubHelpers

  def internal_ai_opts
    {
      classify_non_agent: ->(_env) { "in_app_ai" },
      resolve_data_owner_id: ->(_env) { "user_8842" }
    }
  end

  def test_allows_when_granted
    verdict = { "caller_class" => "in_app_ai", "granted" => true, "source" => "setting", "evaluated_at" => "x" }
    env = {}
    status, _h, _b = build_middleware(ok_app, ok_response(verdict), **internal_ai_opts).call(env)

    assert_equal 200, status
    assert_equal "in_app_ai", env["agentadmit.auth_type"]
    assert_equal true, env["agentadmit.consent"]["granted"]
  end

  def test_denies_when_denied
    verdict = { "caller_class" => "in_app_ai", "granted" => false, "source" => "setting", "evaluated_at" => "x" }
    status, _h, body = build_middleware(ok_app, ok_response(verdict), **internal_ai_opts).call({})

    assert_equal 403, status
    assert_equal "consent_not_granted", parse(body)["error"]
  end

  def test_fails_closed_when_ledger_unreachable
    status, _h, body = build_middleware(ok_app, nil, **internal_ai_opts).call({})

    assert_equal 503, status
    assert_equal "consent_unavailable", parse(body)["error"]
  end

  def test_requires_owner_resolver
    status, _h, _b = build_middleware(ok_app, nil, classify_non_agent: ->(_env) { "in_app_ai" }).call({})
    assert_equal 500, status
  end
end

class CallerConsentHumanTest < Minitest::Test
  include CallerConsentStubHelpers

  def test_defers_without_ledger_call
    calls = 0
    counter = -> { calls += 1 }
    env = human_env
    status, _h, _b = build_middleware(ok_app, nil, ledger_calls: counter).call(env)

    assert_equal 200, status, "human path must continue by default"
    assert_equal "human_session", env["agentadmit.caller_class"]
    assert_equal "user", env["agentadmit.auth_type"]
    assert_equal 0, calls, "Branch A is the app's own model; no ledger call"
  end

  def test_gated_when_gate_human_set
    verdict = { "caller_class" => "human_session", "granted" => false, "source" => "setting", "evaluated_at" => "x" }
    status, _h, body = build_middleware(ok_app, ok_response(verdict),
      gate_human: true, resolve_data_owner_id: ->(_env) { "user_1" }).call(human_env)

    assert_equal 403, status
    assert_equal "consent_not_granted", parse(body)["error"]
  end
end
