# frozen_string_literal: true

# Tests for the declared purpose: the user-facing reason recorded on the
# grant at the consent moment. Review-time record only, never an enforcement
# input; authorization decisions ride scopes, connection status, and consent.
#
# Covers: issue_token sending/omitting "purpose" in the request body, the
# 300-character ArgumentError guard, and verify passing the nullable purpose
# through to IntrospectionResult.

require "minitest/autorun"
require "json"
require_relative "../lib/agentadmit"

# ---------------------------------------------------------------------------
# issue_token: outbound "purpose" field (mirrors TokensClientTest in
# webhook_test.rb -- stub #post to capture the body, no HTTP round-trip)
# ---------------------------------------------------------------------------
class IssueTokenPurposeTest < Minitest::Test
  def config
    config = AgentAdmit::Config.new
    config.api_key = "aa_test_abc"
    config.app_id = "app_test"
    config
  end

  def test_purpose_included_in_body_when_provided
    body = issue_body(purpose: "Book quarterly travel for the sales team")
    assert_equal "Book quarterly travel for the sales team", body["purpose"]
  end

  def test_purpose_omitted_when_not_given
    body = issue_body
    refute_includes body.keys, "purpose"
  end

  def test_purpose_omitted_when_nil
    body = issue_body(purpose: nil)
    refute_includes body.keys, "purpose"
  end

  def test_purpose_at_exactly_300_chars_is_accepted
    body = issue_body(purpose: "p" * 300)
    assert_equal "p" * 300, body["purpose"]
  end

  def test_purpose_over_300_chars_raises_argument_error
    error = assert_raises(ArgumentError) do
      issue_body(purpose: "p" * 301)
    end
    assert_match(/300/, error.message)
  end

  private

  # Build the issue_token request body without an HTTP round-trip.
  def issue_body(**kwargs)
    captured = nil
    client = AgentAdmit::TokensClient.new(config)
    client.define_singleton_method(:post) do |_path, body, **|
      captured = body
      {}
    end
    client.issue_token(user_id: "user_1", scopes: ["read:orders"], **kwargs)
    captured
  end
end

# ---------------------------------------------------------------------------
# verify: nullable purpose passes through to IntrospectionResult (mirrors
# PresenceStubHelpers -- stub #build_http with a fake response)
# ---------------------------------------------------------------------------
class VerifyPurposePassThroughTest < Minitest::Test
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

  def verify_with(body)
    resp = FakeResponse.new("200", {}, JSON.generate(body))
    build_client(resp).verify("ag_at_dummy")
  end

  def test_purpose_string_reaches_the_caller
    result = verify_with(ok_verify_body("purpose" => "Book quarterly travel"))
    assert_equal "Book quarterly travel", result.purpose
  end

  def test_absent_purpose_is_nil
    result = verify_with(ok_verify_body)
    assert_nil result.purpose
  end

  def test_explicit_null_purpose_is_nil
    result = verify_with(ok_verify_body("purpose" => nil))
    assert_nil result.purpose
  end

  def test_non_string_purpose_is_dropped
    # Review-time record, never an enforcement input -- a malformed value is
    # simply dropped rather than failing the verify.
    result = verify_with(ok_verify_body("purpose" => { "text" => "x" }))
    assert_nil result.purpose
  end
end
