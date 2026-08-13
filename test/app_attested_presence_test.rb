# frozen_string_literal: true

# Tests for app-attested presence: typed forwarding at token issuance
# (v1.9.0).
#
# issue_token must include the full literal-true wire object
# presence {verified: true, uv: true, method, verified_at} when an
# AppAttestedPresence is provided (verified_at RFC 3339 with explicit offset:
# Ruby Time/DateTime always carry one, so the offset-less-timestamp outage
# class is unrepresentable here), omit the key entirely when nil (omitting
# the field is the only way to say "no ceremony"), and reject a raw Hash so
# the wire contract stays owned by the typed class. AppAttestedPresence
# rejects an out-of-contract method (^[a-z0-9_]+$, 1-60) and a non-timestamp
# verified_at at construction, before any request.

require "minitest/autorun"
require "json"
require "time"
require_relative "../lib/agentadmit"

CEREMONY_AT = Time.utc(2026, 8, 13, 17, 0, 0)

class AppAttestedPresenceModelTest < Minitest::Test
  def test_to_wire_is_the_exact_hosted_contract_shape
    fact = AgentAdmit::AppAttestedPresence.new(method: "my_webauthn", verified_at: CEREMONY_AT)
    assert_equal(
      {
        "verified" => true,
        "uv" => true,
        "method" => "my_webauthn",
        "verified_at" => "2026-08-13T17:00:00Z"
      },
      fact.to_wire
    )
  end

  def test_non_utc_offset_is_preserved
    pacific = Time.new(2026, 8, 13, 10, 0, 0, "-07:00")
    fact = AgentAdmit::AppAttestedPresence.new(method: "my_webauthn", verified_at: pacific)
    assert_equal "2026-08-13T10:00:00-07:00", fact.to_wire["verified_at"]
  end

  def test_datetime_is_accepted
    fact = AgentAdmit::AppAttestedPresence.new(
      method: "my_webauthn",
      verified_at: DateTime.iso8601("2026-08-13T17:00:00+00:00")
    )
    assert_equal "2026-08-13T17:00:00+00:00", fact.to_wire["verified_at"]
  end

  def test_out_of_contract_methods_raise_at_construction
    ["My_WebAuthn", "my webauthn", "my-webauthn", "", "m" * 61, nil, 42].each do |bad|
      error = assert_raises(ArgumentError, "method #{bad.inspect} must be rejected") do
        AgentAdmit::AppAttestedPresence.new(method: bad, verified_at: CEREMONY_AT)
      end
      assert_match(/method must be/, error.message)
    end
  end

  def test_non_timestamp_verified_at_raises_at_construction
    ["2026-08-13T17:00:00Z", nil, 1_755_104_400].each do |bad|
      error = assert_raises(ArgumentError, "verified_at #{bad.inspect} must be rejected") do
        AgentAdmit::AppAttestedPresence.new(method: "my_webauthn", verified_at: bad)
      end
      assert_match(/verified_at must be/, error.message)
    end
  end
end

class IssueTokenAppAttestedPresenceTest < Minitest::Test
  def config
    config = AgentAdmit::Config.new
    config.api_key = "aa_test_abc"
    config.app_id = "app_test"
    config
  end

  def test_presence_included_as_literal_true_wire_object
    fact = AgentAdmit::AppAttestedPresence.new(method: "my_webauthn", verified_at: CEREMONY_AT)
    body = issue_body(presence: fact)
    assert_equal(
      {
        "verified" => true,
        "uv" => true,
        "method" => "my_webauthn",
        "verified_at" => "2026-08-13T17:00:00Z"
      },
      body["presence"]
    )
  end

  def test_presence_omitted_when_not_given
    body = issue_body
    refute_includes body.keys, "presence"
  end

  def test_presence_omitted_when_nil
    body = issue_body(presence: nil)
    refute_includes body.keys, "presence"
  end

  def test_raw_hash_presence_raises_before_any_request
    # Typed-only: a hand-rolled Hash shaped exactly like the wire format is
    # rejected so the contract stays owned by AppAttestedPresence.
    error = assert_raises(ArgumentError) do
      issue_body(presence: {
                   "verified" => true, "uv" => true,
                   "method" => "my_webauthn", "verified_at" => "2026-08-13T17:00:00Z"
                 })
    end
    assert_match(/AppAttestedPresence/, error.message)
    refute @post_called, "issue_token must raise before any request is sent"
  end

  def test_presence_travels_alongside_purpose_and_user_intent
    fact = AgentAdmit::AppAttestedPresence.new(method: "my_webauthn", verified_at: CEREMONY_AT)
    body = issue_body(purpose: "App's words", user_intent: "User's words", presence: fact)
    assert_equal "App's words", body["purpose"]
    assert_equal "User's words", body["user_intent"]
    assert_equal true, body["presence"]["verified"]
  end

  private

  # Build the issue_token request body without an HTTP round-trip (mirrors
  # user_intent_test.rb). Records whether #post was reached in @post_called
  # so raise-path tests can assert validation fires before any request.
  def issue_body(**kwargs)
    captured = nil
    @post_called = false
    test = self
    client = AgentAdmit::TokensClient.new(config)
    client.define_singleton_method(:post) do |_path, body, **|
      test.instance_variable_set(:@post_called, true)
      captured = body
      {}
    end
    client.issue_token(user_id: "user_1", scopes: ["read:orders"], **kwargs)
    captured
  end
end
