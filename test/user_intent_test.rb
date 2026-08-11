# frozen_string_literal: true

# Tests for user-declared intent: the user's OWN words, typed at the consent
# moment (purpose is the app's words; user_intent is the user's). Review-time
# record only, never an enforcement input; authorization decisions ride
# scopes, connection status, and consent.
#
# Covers: issue_token sending/omitting "user_intent" in the request body, the
# metadata-tolerance normalization (malformed / empty / over-300 values
# normalize to nil and are omitted -- never a rejection, unlike purpose's
# ArgumentError), and verify passing the nullable user_intent through to
# IntrospectionResult.

require "minitest/autorun"
require "json"
require_relative "../lib/agentadmit"

# ---------------------------------------------------------------------------
# issue_token: outbound "user_intent" field (mirrors IssueTokenPurposeTest in
# purpose_test.rb -- stub #post to capture the body, no HTTP round-trip)
# ---------------------------------------------------------------------------
class IssueTokenUserIntentTest < Minitest::Test
  def config
    config = AgentAdmit::Config.new
    config.api_key = "aa_test_abc"
    config.app_id = "app_test"
    config
  end

  def test_user_intent_included_in_body_when_provided
    body = issue_body(user_intent: "Book my flights to the Austin offsite")
    assert_equal "Book my flights to the Austin offsite", body["user_intent"]
  end

  def test_user_intent_omitted_when_not_given
    body = issue_body
    refute_includes body.keys, "user_intent"
  end

  def test_user_intent_omitted_when_nil
    body = issue_body(user_intent: nil)
    refute_includes body.keys, "user_intent"
  end

  def test_user_intent_at_exactly_300_chars_is_accepted
    body = issue_body(user_intent: "i" * 300)
    assert_equal "i" * 300, body["user_intent"]
  end

  def test_user_intent_over_300_chars_normalizes_to_nil_without_raising
    # Metadata tolerance: unlike purpose (which raises ArgumentError over
    # 300), a too-long user_intent normalizes to nil and is omitted.
    body = issue_body(user_intent: "i" * 301)
    refute_includes body.keys, "user_intent"
  end

  def test_empty_string_user_intent_normalizes_to_nil
    body = issue_body(user_intent: "")
    refute_includes body.keys, "user_intent"
  end

  def test_whitespace_only_user_intent_normalizes_to_nil
    body = issue_body(user_intent: "   \n\t ")
    refute_includes body.keys, "user_intent"
  end

  def test_non_string_user_intent_normalizes_to_nil
    body = issue_body(user_intent: { "text" => "x" })
    refute_includes body.keys, "user_intent"
  end

  def test_user_intent_and_purpose_travel_independently
    body = issue_body(purpose: "App's words", user_intent: "User's words")
    assert_equal "App's words", body["purpose"]
    assert_equal "User's words", body["user_intent"]
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
# verify: nullable user_intent passes through to IntrospectionResult (mirrors
# VerifyPurposePassThroughTest -- stub #build_http with a fake response)
# ---------------------------------------------------------------------------
class VerifyUserIntentPassThroughTest < Minitest::Test
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

  def test_user_intent_string_reaches_the_caller
    result = verify_with(ok_verify_body("user_intent" => "Book my flights"))
    assert_equal "Book my flights", result.user_intent
  end

  def test_absent_user_intent_is_nil
    result = verify_with(ok_verify_body)
    assert_nil result.user_intent
  end

  def test_explicit_null_user_intent_is_nil
    result = verify_with(ok_verify_body("user_intent" => nil))
    assert_nil result.user_intent
  end

  def test_non_string_user_intent_is_dropped
    # Review-time record, never an enforcement input -- a malformed value is
    # simply dropped rather than failing the verify.
    result = verify_with(ok_verify_body("user_intent" => { "text" => "x" }))
    assert_nil result.user_intent
  end

  def test_user_intent_and_purpose_are_distinct_fields
    result = verify_with(ok_verify_body(
      "purpose" => "App's words",
      "user_intent" => "User's words"
    ))
    assert_equal "App's words", result.purpose
    assert_equal "User's words", result.user_intent
  end
end
