# frozen_string_literal: true

# Regression tests for 429 retry handling in IntrospectionClient#verify.
#
# A server-supplied Retry-After header is untrusted input: a compromised or
# misconfigured endpoint could send `Retry-After: 3600` and pin the caller's
# request thread for an hour. Every wait must be capped at 30 seconds, and
# cumulative wait across retries of one verify call must be capped at 120
# seconds.

require "minitest/autorun"
require "json"
require_relative "../lib/agentadmit"

class RateLimitRetryTest < Minitest::Test
  FakeResponse = Struct.new(:code, :headers, :body) do
    def [](name)
      headers[name]
    end
  end

  def rate_limited(retry_after)
    FakeResponse.new("429", { "Retry-After" => retry_after.to_s }, "{}")
  end

  def ok_response
    FakeResponse.new("200", {}, JSON.generate(
      "active" => true, "user_id" => "user_1", "connection_id" => "conn_1",
      "scopes" => ["read:things"], "agent_label" => "Test Agent"
    ))
  end

  # Build a client whose HTTP layer replays canned responses (repeating the
  # last one), records sleeps instead of sleeping, and has zero jitter.
  def stubbed_client(responses, max_retries: 3)
    config = AgentAdmit::Config.new
    config.app_id = "app_test"
    config.api_key = "aa_test_key"
    config.max_retries = max_retries

    client = AgentAdmit::IntrospectionClient.new(config)

    fake_http = Object.new
    calls = []
    fake_http.define_singleton_method(:request) do |_req|
      calls << 1
      responses[[calls.length - 1, responses.length - 1].min]
    end

    sleeps = []
    client.define_singleton_method(:build_http) { |_uri| fake_http }
    client.define_singleton_method(:sleep) { |s| sleeps << s }
    client.define_singleton_method(:rand) { |_range| 250 }
    client.define_singleton_method(:warn) { |_msg| nil }

    [client, sleeps, calls]
  end

  def test_huge_retry_after_is_capped_at_30s
    client, sleeps, = stubbed_client([rate_limited(3600)])

    error = assert_raises(AgentAdmit::RateLimitError) do
      client.verify("ag_at_dummy")
    end

    assert_match(/Max retries/, error.message)
    assert_equal 3, sleeps.length
    sleeps.each do |slept|
      assert_operator slept, :<=, 30.5, "wait must be capped, got #{slept}s"
    end
  end

  def test_cumulative_budget_exhausted
    # High max_retries so the 120s budget, not the retry count, is the limiter.
    client, sleeps, calls = stubbed_client([rate_limited(30)], max_retries: 99)

    error = assert_raises(AgentAdmit::RateLimitError) do
      client.verify("ag_at_dummy")
    end

    assert_match(/budget/, error.message)
    # 30.25s per wait -> 3 sleeps (90.75s); the 4th would exceed 120s.
    assert_equal 3, sleeps.length
    assert_equal 4, calls.length
  end

  def test_recovers_when_server_stops_rate_limiting
    client, sleeps, calls = stubbed_client([rate_limited(2), ok_response])

    result = client.verify("ag_at_dummy")

    assert_equal "conn_1", result.connection_id
    assert_equal ["read:things"], result.scopes
    assert_equal 2, calls.length
    assert_equal [2.25], sleeps
  end
end
