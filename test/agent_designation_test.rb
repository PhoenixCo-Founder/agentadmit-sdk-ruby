# frozen_string_literal: true

require "minitest/autorun"
require "json"
require_relative "../lib/agentadmit"

# ---------------------------------------------------------------------------
# Agent designation (1.14.0): what the USER said the connection is for
# (designated_agent) and what the AGENT reported about itself
# (agent_reported) pass through verify to IntrospectionResult. Review-time
# records only -- a malformed block is dropped and never fails the verify.
# ---------------------------------------------------------------------------
class VerifyAgentDesignationPassThroughTest < Minitest::Test
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
      "agent_label" => "my-agent"
    }.merge(overrides)
  end

  def verify_with(body)
    resp = FakeResponse.new("200", {}, JSON.generate(body))
    build_client(resp).verify("ag_at_dummy")
  end

  LISTED = {
    "agent_id" => "agt_openclaw",
    "name" => "OpenClaw",
    "source" => "user_declared",
    "model" => { "model_id" => "mdl_claude", "name" => "Claude (Anthropic)" }
  }.freeze

  def test_user_designation_reaches_the_caller
    result = verify_with(ok_verify_body("designated_agent" => LISTED))
    assert_equal LISTED, result.designated_agent
  end

  def test_agent_label_stays_separate_from_the_designation
    result = verify_with(ok_verify_body("designated_agent" => LISTED))
    assert_equal "my-agent", result.agent_label
    assert_equal "OpenClaw", result.designated_agent["name"]
  end

  def test_typed_name_has_nil_agent_id_and_no_model_is_nil
    result = verify_with(ok_verify_body(
      "designated_agent" => { "agent_id" => nil, "name" => "My Home Agent",
                              "source" => "user_declared", "model" => nil }
    ))
    assert_nil result.designated_agent["agent_id"]
    assert_equal "My Home Agent", result.designated_agent["name"]
    assert_nil result.designated_agent["model"]
  end

  def test_wire_null_is_no_designation
    result = verify_with(ok_verify_body("designated_agent" => nil, "agent_reported" => nil))
    assert_nil result.designated_agent
    assert_nil result.agent_reported
  end

  def test_absent_fields_are_nil_for_older_servers
    result = verify_with(ok_verify_body)
    assert_nil result.designated_agent
    assert_nil result.agent_reported
  end

  def test_agent_reported_reaches_the_caller
    reported = { "platform" => "openclaw",
                 "model" => { "id" => "claude-fable-5-1", "version" => "2026-09" } }
    result = verify_with(ok_verify_body("agent_reported" => reported))
    assert_equal reported, result.agent_reported
  end

  def test_both_records_are_carried_independently
    reported = { "platform" => "other-runtime", "model" => { "id" => "gpt-6", "version" => nil } }
    result = verify_with(ok_verify_body("designated_agent" => LISTED, "agent_reported" => reported))
    assert_equal "OpenClaw", result.designated_agent["name"]
    assert_equal "other-runtime", result.agent_reported["platform"]
    assert_equal "gpt-6", result.agent_reported["model"]["id"]
  end

  def test_malformed_designation_is_dropped_and_never_fails_the_call
    [
      "OpenClaw",
      ["OpenClaw"],
      42,
      { "name" => "OpenClaw" },
      { "name" => "OpenClaw", "source" => "verified" },
      { "name" => "", "source" => "user_declared" },
      { "name" => 7, "source" => "user_declared" }
    ].each do |bad|
      result = verify_with(ok_verify_body("designated_agent" => bad, "agent_reported" => "x"))
      assert_nil result.designated_agent, "expected #{bad.inspect} to be dropped"
      assert_nil result.agent_reported
      assert_equal "user_1", result.user_id
      assert_equal ["read:orders"], result.scopes
    end
  end
end

class ParseDesignatedAgentTest < Minitest::Test
  def parse(raw)
    AgentAdmit::IntrospectionClient.parse_designated_agent(raw)
  end

  def test_reads_a_listed_app_and_model
    out = parse("agent_id" => "agt_1", "name" => "OpenClaw", "source" => "user_declared",
                "model" => { "model_id" => "mdl_1", "name" => "Claude (Anthropic)" })
    assert_equal({ "agent_id" => "agt_1", "name" => "OpenClaw", "source" => "user_declared",
                   "model" => { "model_id" => "mdl_1", "name" => "Claude (Anthropic)" } }, out)
  end

  def test_malformed_model_is_dropped_and_the_app_is_kept
    ["Claude", { "model_id" => "mdl_1" }, { "name" => "" }, { "name" => 5 }, []].each do |bad|
      out = parse("agent_id" => "agt_1", "name" => "OpenClaw", "source" => "user_declared",
                  "model" => bad)
      assert_equal "OpenClaw", out["name"]
      assert_nil out["model"], "expected model #{bad.inspect} to be dropped"
    end
  end

  def test_model_named_without_a_listed_id_has_nil_model_id
    out = parse("name" => "OpenClaw", "source" => "user_declared",
                "model" => { "model_id" => 9, "name" => "A local model" })
    assert_nil out["agent_id"]
    assert_equal({ "model_id" => nil, "name" => "A local model" }, out["model"])
  end

  def test_unknown_keys_are_not_carried
    out = parse("name" => "OpenClaw", "source" => "user_declared", "verified" => true)
    assert_equal %w[agent_id model name source], out.keys.sort
  end

  def test_returns_nil_for_anything_that_is_not_a_user_declared_designation
    [nil, "x", 1, [], {}, { "name" => "A" }, { "name" => "A", "source" => "operator_verified" },
     { "source" => "user_declared" }].each do |bad|
      assert_nil parse(bad), "expected #{bad.inspect} to be nil"
    end
  end
end

class ParseAgentReportedTest < Minitest::Test
  def parse(raw)
    AgentAdmit::IntrospectionClient.parse_agent_reported(raw)
  end

  def test_reads_platform_and_model
    out = parse("platform" => "openclaw", "model" => { "id" => "claude-fable-5-1", "version" => "5.1" })
    assert_equal({ "platform" => "openclaw",
                   "model" => { "id" => "claude-fable-5-1", "version" => "5.1" } }, out)
  end

  def test_platform_only_model_only_and_a_non_string_version
    assert_equal({ "platform" => "openclaw", "model" => nil }, parse("platform" => "openclaw"))
    assert_equal({ "platform" => nil, "model" => { "id" => "m", "version" => nil } },
                 parse("model" => { "id" => "m" }))
    assert_equal({ "platform" => nil, "model" => { "id" => "m", "version" => nil } },
                 parse("platform" => 3, "model" => { "id" => "m", "version" => 5.1 }))
  end

  def test_returns_nil_when_it_carries_neither_a_platform_nor_a_model_id
    [nil, "x", [], {}, { "platform" => "" }, { "model" => {} }, { "model" => { "version" => "1" } },
     { "platform" => nil, "model" => { "id" => "" } }].each do |bad|
      assert_nil parse(bad), "expected #{bad.inspect} to be nil"
    end
  end
end
