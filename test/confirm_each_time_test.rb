# frozen_string_literal: true

require "minitest/autorun"
require "json"
require "stringio"
require_relative "../lib/agentadmit"

module ConfirmEachTimeHelpers
  FakeResponse = Struct.new(:code, :headers, :body) do
    def [](name)
      headers[name]
    end
  end

  def config
    cfg = AgentAdmit::Config.new
    cfg.app_id = "app_test"
    cfg.api_key = "aa_test_key"
    cfg
  end

  def active(extra = {})
    { "active" => true, "user_id" => "user_1", "connection_id" => "conn_1",
      "scopes" => ["write:payments"], "agent_label" => "Test Agent" }.merge(extra)
  end

  def response(body)
    FakeResponse.new("200", {}, JSON.generate(body))
  end

  def client_for(body, requests = [])
    client = AgentAdmit::IntrospectionClient.new(config)
    fake_response = response(body)
    fake_http = Object.new
    fake_http.define_singleton_method(:request) do |request|
      requests << request
      fake_response
    end
    client.define_singleton_method(:build_http) { |_uri| fake_http }
    client
  end

  def confirmation
    { "action_session_id" => "asess_abc",
      "action_session_url" => "https://agentadmit.com/confirm/action/asess_abc",
      "expires_at" => "2026-09-03T22:00:00Z", "scope" => "write:payments",
      "method" => "POST", "endpoint" => "/api/payments",
      "request_digest" => "sha256:deadbeef", "summary" => "Pay Alex $50" }
  end
end

class ConfirmEachTimeClientTest < Minitest::Test
  include ConfirmEachTimeHelpers

  def test_typed_denial_carries_strict_ceremony_without_wire_leaks
    body = active("error" => "confirmation_required", "confirmation" => confirmation,
                  "attestation_status" => "action_mismatch",
                  "attestation_description" => "Different action.",
                  "renewal" => "Confirm with a passkey.", "secret" => "no")
    error = assert_raises(AgentAdmit::ConfirmationRequiredError) do
      client_for(body).verify("ag_at_dummy", scope_used: "write:payments")
    end

    assert_kind_of AgentAdmit::ActiveDenialError, error
    assert_equal confirmation, error.confirmation
    assert_equal "action_mismatch", error.attestation_status
    assert_equal "confirmation_required", error.denial_body["error"]
    refute error.denial_body.key?("secret")
  end

  def test_malformed_ceremony_is_a_plain_fail_closed_denial
    body = active("error" => "confirmation_required",
                  "confirmation" => { "action_session_id" => 17 })
    error = assert_raises(AgentAdmit::ActiveDenialError) do
      client_for(body).verify("ag_at_dummy")
    end
    refute_kind_of AgentAdmit::ConfirmationRequiredError, error
    refute error.denial_body.key?("confirmation")
  end

  def test_confirm_fields_are_forwarded_trimmed_capped_and_omitted_when_empty
    requests = []
    client_for(active, requests).verify(
      "ag_at_dummy", action_attestation_id: "  #{'a' * 150}  ",
      request_digest: "sha256:#{'b' * 200}", action_summary: "  #{'s' * 250}  "
    )
    sent = JSON.parse(requests.first.body)
    assert_equal 120, sent["action_attestation_id"].length
    assert_equal 128, sent["request_digest"].length
    assert_equal 200, sent["action_summary"].length

    requests = []
    client_for(active, requests).verify(
      "ag_at_dummy", action_attestation_id: " ", request_digest: "", action_summary: nil
    )
    assert_equal({ "token" => "ag_at_dummy" }, JSON.parse(requests.first.body))
  end

  def test_consumed_confirmation_parsing_is_strict
    result = client_for(active("action_confirmation" =>
      { "action_session_id" => "asess_abc", "consumed" => true })).verify("ag_at_dummy")
    assert result.action_confirmed?
    assert_equal "asess_abc", result.action_confirmation["action_session_id"]

    [{ "action_session_id" => "asess_abc", "consumed" => false },
     { "action_session_id" => 7, "consumed" => true },
     { "action_session_id" => "asess_abc", "consumed" => "true" }].each do |block|
      refute client_for(active("action_confirmation" => block)).verify("ag_at_dummy").action_confirmed?
    end
  end

  def test_parser_keeps_nullable_fields_as_nil
    minimal = { "action_session_id" => "a", "action_session_url" => "u",
                "expires_at" => "e", "scope" => "s" }
    parsed = AgentAdmit::IntrospectionClient.parse_action_confirmation(minimal)
    assert_nil parsed["method"]
    assert_nil parsed["endpoint"]
    assert_nil parsed["request_digest"]
    assert_nil parsed["summary"]
  end
end

class ConfirmEachTimeMiddlewareTest < Minitest::Test
  include ConfirmEachTimeHelpers

  def setup
    AgentAdmit.configuration = config
  end

  def teardown
    AgentAdmit.configuration = nil
  end

  def build(body, requests, **options)
    app_calls = []
    app = lambda do |env|
      app_calls << { confirmation: env["agentadmit.action_confirmation"],
                     body: env["rack.input"].read }
      [200, {}, ["ok"]]
    end
    middleware = AgentAdmit::Middleware.new(app, **options)
    middleware.instance_variable_set(:@client, client_for(body, requests))
    [middleware, app_calls]
  end

  def env(body = '{"trainer":"Alex","amount":50}')
    { "HTTP_AUTHORIZATION" => "Bearer ag_at_dummy",
      "HTTP_X_AGENTADMIT_ACTION_ATTESTATION" => " asess_abc ",
      "PATH_INFO" => "/api/payments", "REQUEST_METHOD" => "POST",
      "rack.input" => StringIO.new(body) }
  end

  def test_summary_route_sends_digest_forwards_header_and_rewinds_body
    raw = '{"trainer":"Alex","amount":50}'
    requests = []
    middleware, app_calls = build(
      active("action_confirmation" =>
        { "action_session_id" => "asess_abc", "consumed" => true }),
      requests,
      scope_for: "write:payments",
      action_summary: ->(_env) { "Pay Alex $50" }
    )

    status, = middleware.call(env(raw))
    assert_equal 200, status
    sent = JSON.parse(requests.first.body)
    assert_equal "asess_abc", sent["action_attestation_id"]
    assert_equal "sha256:#{Digest::SHA256.hexdigest(raw)}", sent["request_digest"]
    assert_equal "Pay Alex $50", sent["action_summary"]
    assert_equal raw, app_calls.first[:body]
    assert_equal true, app_calls.first[:confirmation]["consumed"]
  end

  def test_plain_route_still_forwards_attestation_but_omits_digest_and_summary
    requests = []
    middleware, = build(active, requests, scope_for: "write:payments")
    middleware.call(env)
    sent = JSON.parse(requests.first.body)
    assert_equal "asess_abc", sent["action_attestation_id"]
    refute sent.key?("request_digest")
    refute sent.key?("action_summary")
  end

  def test_confirmation_required_becomes_403_and_app_does_not_run
    requests = []
    middleware, app_calls = build(
      active("error" => "confirmation_required", "confirmation" => confirmation),
      requests,
      scope_for: "write:payments",
      action_summary: "Pay Alex $50"
    )
    status, _headers, chunks = middleware.call(env)
    body = JSON.parse(chunks.first)
    assert_equal 403, status
    assert_equal "confirmation_required", body["error"]
    assert_equal "asess_abc", body.dig("confirmation", "action_session_id")
    assert_empty app_calls
  end
end

class ConfirmEachTimeVerifyUrlTest < Minitest::Test
  def with_clean_urls
    old_api = ENV.delete("AGENTADMIT_API_URL")
    old_verify = ENV.delete("AGENTADMIT_VERIFY_URL")
    yield
  ensure
    ENV["AGENTADMIT_API_URL"] = old_api if old_api
    ENV["AGENTADMIT_VERIFY_URL"] = old_verify if old_verify
  end

  def test_non_default_api_url_derives_verify_url_and_explicit_verify_wins
    with_clean_urls do
      cfg = AgentAdmit::Config.new
      cfg.api_url = "http://127.0.0.1:3003/"
      assert_equal "http://127.0.0.1:3003/api/v1/verify", cfg.verify_url

      cfg.verify_url = "http://127.0.0.1:9999/verify"
      cfg.api_url = "http://127.0.0.1:4000"
      assert_equal "http://127.0.0.1:9999/verify", cfg.verify_url
    end
  end
end
