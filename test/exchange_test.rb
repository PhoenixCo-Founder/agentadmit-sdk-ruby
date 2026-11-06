# frozen_string_literal: true

require "minitest/autorun"
require "json"
require_relative "../lib/agentadmit"

# ---------------------------------------------------------------------------
# TokensClient#exchange (1.14.1): what the agent says it runs on
# (agent_platform, agent_model) is passed along to the hosted exchange when
# given and omitted when not. The exchange never sends the operator API key.
# ---------------------------------------------------------------------------
class ExchangeSelfReportTest < Minitest::Test
  def exchange_call(*args, **kwargs)
    cfg = AgentAdmit::Config.new
    cfg.app_id = "app_test"
    cfg.api_key = "aa_test_key"
    client = AgentAdmit::TokensClient.new(cfg)
    captured = {}
    client.define_singleton_method(:post) do |path, body, authenticated:, op:|
      captured[:path] = path
      captured[:body] = body
      captured[:authenticated] = authenticated
      captured[:op] = op
      { "access_token" => "ag_at_x" }
    end
    result = client.exchange(*args, **kwargs)
    [result, captured]
  end

  def test_bare_exchange_sends_only_the_token_and_no_api_key
    result, captured = exchange_call("ag_ct_abc")
    assert_equal "ag_at_x", result["access_token"]
    assert_equal "/api/v1/exchange", captured[:path]
    assert_equal({ "token" => "ag_ct_abc" }, captured[:body])
    assert_equal false, captured[:authenticated]
  end

  def test_forwards_what_the_agent_says_it_runs_on
    _, captured = exchange_call(
      "ag_ct_abc",
      agent_label: "My Agent",
      agent_platform: "ExampleAgent 2.1",
      agent_model: { "id" => "example-model", "version" => "2026-01" }
    )
    assert_equal(
      { "token" => "ag_ct_abc",
        "agent_label" => "My Agent",
        "agent_platform" => "ExampleAgent 2.1",
        "agent_model" => { "id" => "example-model", "version" => "2026-01" } },
      captured[:body]
    )
  end

  def test_nil_self_report_is_omitted
    _, captured = exchange_call("ag_ct_abc", agent_id: "agent_1", agent_platform: nil, agent_model: nil)
    assert_equal({ "token" => "ag_ct_abc", "agent_id" => "agent_1" }, captured[:body])
  end

  def test_body_serializes_without_nulls
    _, captured = exchange_call("ag_ct_abc", agent_model: { "id" => "example-model" })
    refute_includes JSON.generate(captured[:body]), "null"
  end
end
