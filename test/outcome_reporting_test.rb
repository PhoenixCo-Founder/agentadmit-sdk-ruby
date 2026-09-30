# frozen_string_literal: true

require "minitest/autorun"
require "json"
require_relative "../lib/agentadmit"

class OutcomeReportingTest < Minitest::Test
  FakeResponse = Struct.new(:code, :headers, :body) do
    def [](name)
      headers[name]
    end
  end

  def stub_config
    cfg = AgentAdmit::Config.new
    cfg.app_id = "app_test"
    cfg.api_key = "aa_test_key"
    cfg.api_url = "http://localhost:9292"
    cfg.verify_url = "http://localhost:9292/api/v1/verify"
    cfg
  end

  def ok_verify_body(overrides = {})
    {
      "active" => true,
      "user_id" => "user_1",
      "connection_id" => "conn_1",
      "scopes" => ["write:payments"],
      "agent_label" => "Test Agent"
    }.merge(overrides)
  end

  def client_with_responses(*responses, requests:)
    queue = responses.dup
    client = AgentAdmit::IntrospectionClient.new(stub_config)
    fake_http = Object.new
    fake_http.define_singleton_method(:request) do |req|
      requests << req
      queue.shift
    end
    client.define_singleton_method(:build_http) { |_uri| fake_http }
    client
  end

  def json_response(body, status = "200")
    FakeResponse.new(status, {}, JSON.generate(body))
  end

  def request_body(req)
    JSON.parse(req.body)
  end

  def test_verify_surfaces_audit_row_id_and_consumed_receipt
    requests = []
    client = client_with_responses(
      json_response(ok_verify_body(
        "audit_row_id" => "11111111-1111-4111-8111-111111111111",
        "consumed_receipt" => {
          "consumed_at" => "2026-09-30T02:54:07.000Z",
          "connection_id" => "conn_123",
          "chain_seq" => nil,
          "row_hash" => nil
        }
      )),
      requests: requests
    )

    result = client.verify("ag_at_dummy")

    assert_equal "11111111-1111-4111-8111-111111111111", result.audit_row_id
    assert_equal({
      "consumed_at" => "2026-09-30T02:54:07.000Z",
      "connection_id" => "conn_123",
      "chain_seq" => nil,
      "row_hash" => nil
    }, result.consumed_receipt)
    refute result.action_confirmed?,
      "an already-consumed receipt is only a replay diagnostic, not authorization"
  end

  def test_report_outcome_posts_expected_body_and_returns_hosted_response
    requests = []
    client = client_with_responses(
      json_response(
        "outcome_row_id" => "22222222-2222-4222-8222-222222222222",
        "outcome" => "executed",
        "status_class" => "2xx",
        "chain_seq" => 12,
        "row_hash" => "abc",
        "reported_at" => "2026-09-30T03:00:00.000Z"
      ),
      requests: requests
    )

    response = client.report_outcome(
      "11111111-1111-4111-8111-111111111111",
      outcome: "executed",
      status_class: "2xx"
    )

    assert_equal "22222222-2222-4222-8222-222222222222", response["outcome_row_id"]
    req = requests.first
    assert_equal "/api/v1/audit/11111111-1111-4111-8111-111111111111/outcome", req.path
    assert_equal "Bearer aa_test_key", req["Authorization"]
    assert_equal({ "outcome" => "executed", "status_class" => "2xx" }, request_body(req))
  end

  def test_report_outcome_allows_explicit_unknown_without_status_class
    requests = []
    client = client_with_responses(
      json_response("outcome_row_id" => "row_out", "outcome" => "unknown", "status_class" => nil),
      requests: requests
    )

    client.report_outcome("row_in", outcome: "unknown")

    assert_equal({ "outcome" => "unknown", "status_class" => nil }, request_body(requests.first))
  end

  def test_report_outcome_validates_inputs
    client = AgentAdmit::IntrospectionClient.new(stub_config)

    assert_raises(ArgumentError) { client.report_outcome("", outcome: "executed") }
    assert_raises(ArgumentError) { client.report_outcome("row", outcome: "maybe") }
    assert_raises(ArgumentError) do
      client.report_outcome("row", outcome: "executed", status_class: "600")
    end
  end
end

class RackOutcomeReportingTest < Minitest::Test
  Result = AgentAdmit::IntrospectionClient::IntrospectionResult

  class FakeClient
    attr_reader :reports
    attr_accessor :raise_on_report

    def initialize(result)
      @result = result
      @reports = []
    end

    def verify(_token, **_opts)
      @result
    end

    def report_outcome(row, outcome:, status_class: nil)
      @reports << [row, outcome, status_class]
      raise "report failed" if raise_on_report

      { "ok" => true }
    end
  end

  def setup
    cfg = AgentAdmit::Config.new
    cfg.app_id = "app_test"
    cfg.api_key = "aa_test_key"
    AgentAdmit.configuration = cfg
  end

  def teardown
    AgentAdmit.configuration = nil
  end

  def result(row: "11111111-1111-4111-8111-111111111111", receipt: nil)
    Result.new(
      user_id: "user_1",
      connection_id: "conn_1",
      scopes: ["write:payments"],
      agent_label: "Test Agent",
      audit_row_id: row,
      consumed_receipt: receipt
    )
  end

  def agent_env
    {
      "HTTP_AUTHORIZATION" => "Bearer ag_at_dummy",
      "PATH_INFO" => "/payments",
      "REQUEST_METHOD" => "POST"
    }
  end

  def middleware(app, client, report_outcome: true)
    mw = AgentAdmit::Middleware.new(app,
                                    scope_for: "write:payments",
                                    report_outcome: report_outcome)
    mw.instance_variable_set(:@client, client)
    mw
  end

  def test_reports_executed_after_success_response_triple
    client = FakeClient.new(result)
    app = ->(_env) { [201, { "Content-Type" => "application/json" }, ['{"ok":true}']] }
    status, = middleware(app, client).call(agent_env)

    assert_equal 201, status
    assert_equal [["11111111-1111-4111-8111-111111111111", "executed", "2xx"]],
                 client.reports
  end

  def test_reports_failed_for_error_status_response_triple
    client = FakeClient.new(result)
    app = ->(_env) { [404, {}, ["missing"]] }
    middleware(app, client).call(agent_env)

    assert_equal [["11111111-1111-4111-8111-111111111111", "failed", "4xx"]],
                 client.reports
  end

  def test_skips_report_when_response_is_missing_or_unobservable
    client = FakeClient.new(result)
    app = ->(_env) { nil }

    assert_nil middleware(app, client).call(agent_env)
    assert_empty client.reports
  end

  def test_skips_report_when_downstream_raises
    client = FakeClient.new(result)
    app = ->(_env) { raise "boom" }

    assert_raises(RuntimeError) { middleware(app, client).call(agent_env) }
    assert_empty client.reports
  end

  def test_reporting_errors_do_not_replace_app_response
    client = FakeClient.new(result)
    client.raise_on_report = true
    app = ->(_env) { [202, {}, ["accepted"]] }

    status = body = nil
    _out, err = capture_io do
      status, _headers, body = middleware(app, client).call(agent_env)
    end

    assert_equal 202, status
    assert_equal ["accepted"], body
    assert_match(/Outcome report failed/, err)
    assert_equal [["11111111-1111-4111-8111-111111111111", "executed", "2xx"]],
                 client.reports
  end

  def test_report_outcome_option_defaults_off
    client = FakeClient.new(result)
    app = ->(_env) { [200, {}, ["ok"]] }
    middleware(app, client, report_outcome: false).call(agent_env)

    assert_empty client.reports
  end

  def test_env_carries_audit_row_and_consumed_receipt_for_downstream_app
    receipt = {
      "consumed_at" => "2026-09-30T02:54:07.000Z",
      "connection_id" => "conn_123",
      "chain_seq" => nil,
      "row_hash" => nil
    }
    client = FakeClient.new(result(receipt: receipt))
    seen = nil
    app = lambda do |env|
      seen = env
      [200, {}, ["ok"]]
    end

    middleware(app, client, report_outcome: false).call(agent_env)

    assert_equal "11111111-1111-4111-8111-111111111111", seen["agentadmit.audit_row_id"]
    assert_equal receipt, seen["agentadmit.consumed_receipt"]
  end
end
