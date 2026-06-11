# frozen_string_literal: true

require "minitest/autorun"
require "openssl"
require "json"
require_relative "../lib/agentadmit"

class WebhookTest < Minitest::Test
  SECRET = "whsec_test123"
  PAYLOAD = '{"event":"agentadmit.alert","alert_type":"usage_spike"}'
  NOW = 1_750_000_000

  def sign(payload, secret: SECRET, ts: NOW)
    digest = OpenSSL::HMAC.hexdigest("SHA256", secret, "#{ts}.#{payload}")
    "t=#{ts},v1=#{digest}"
  end

  def test_valid_signature_passes
    AgentAdmit::Webhook.verify_signature(PAYLOAD, sign(PAYLOAD), SECRET, now: NOW)
  end

  def test_tampered_payload_fails
    error = assert_raises(AgentAdmit::WebhookSignatureError) do
      AgentAdmit::Webhook.verify_signature("#{PAYLOAD} ", sign(PAYLOAD), SECRET, now: NOW)
    end
    assert_match(/verification failed/, error.message)
  end

  def test_wrong_secret_fails
    assert_raises(AgentAdmit::WebhookSignatureError) do
      AgentAdmit::Webhook.verify_signature(PAYLOAD, sign(PAYLOAD, secret: "whsec_other456"), SECRET, now: NOW)
    end
  end

  def test_stale_timestamp_fails
    error = assert_raises(AgentAdmit::WebhookSignatureError) do
      AgentAdmit::Webhook.verify_signature(PAYLOAD, sign(PAYLOAD, ts: NOW - 600), SECRET, now: NOW)
    end
    assert_match(/tolerance/, error.message)
  end

  def test_future_timestamp_fails
    assert_raises(AgentAdmit::WebhookSignatureError) do
      AgentAdmit::Webhook.verify_signature(PAYLOAD, sign(PAYLOAD, ts: NOW + 600), SECRET, now: NOW)
    end
  end

  def test_within_tolerance_passes
    AgentAdmit::Webhook.verify_signature(PAYLOAD, sign(PAYLOAD, ts: NOW - 200), SECRET, now: NOW)
  end

  def test_tolerance_zero_disables_timestamp_check
    AgentAdmit::Webhook.verify_signature(PAYLOAD, sign(PAYLOAD, ts: NOW - 99_999), SECRET, tolerance: 0, now: NOW)
  end

  def test_missing_header_fails
    error = assert_raises(AgentAdmit::WebhookSignatureError) do
      AgentAdmit::Webhook.verify_signature(PAYLOAD, "", SECRET, now: NOW)
    end
    assert_match(/Missing/, error.message)
  end

  def test_malformed_headers_fail
    ["nonsense", "t=abc,v1=def", "t=123", "v1=abc"].each do |header|
      error = assert_raises(AgentAdmit::WebhookSignatureError, "header: #{header}") do
        AgentAdmit::Webhook.verify_signature(PAYLOAD, header, SECRET, now: NOW)
      end
      assert_match(/Malformed/, error.message, "header: #{header}")
    end
  end

  def test_missing_secret_fails
    error = assert_raises(AgentAdmit::WebhookSignatureError) do
      AgentAdmit::Webhook.verify_signature(PAYLOAD, sign(PAYLOAD), "", now: NOW)
    end
    assert_match(/secret/, error.message)
  end

  def test_multiple_candidates_any_match_passes
    AgentAdmit::Webhook.verify_signature(PAYLOAD, "#{sign(PAYLOAD)},v1=deadbeef", SECRET, now: NOW)
  end

  def test_boolean_form
    assert AgentAdmit::Webhook.valid_signature?(PAYLOAD, sign(PAYLOAD), SECRET, now: NOW)
    refute AgentAdmit::Webhook.valid_signature?("#{PAYLOAD}x", sign(PAYLOAD), SECRET, now: NOW)
  end
end

class TokensClientTest < Minitest::Test
  def config
    config = AgentAdmit::Config.new
    config.api_key = "aa_test_abc"
    config.app_id = "app_test"
    config
  end

  def test_unset_duration_omits_field
    body = issue_body
    refute_includes body.keys, "duration_seconds"
  end

  def test_nil_duration_sends_explicit_null
    body = issue_body(duration_seconds: nil)
    assert_includes body.keys, "duration_seconds"
    assert_nil body["duration_seconds"]
    assert_includes JSON.generate(body), '"duration_seconds":null'
  end

  def test_integer_duration_sends_value
    body = issue_body(duration_seconds: 3600)
    assert_equal 3600, body["duration_seconds"]
  end

  def test_bad_api_key_prefix_rejected
    bad = AgentAdmit::Config.new
    bad.api_key = "sk_bad_prefix"
    assert_raises(AgentAdmit::ConfigurationError) { AgentAdmit::TokensClient.new(bad) }
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
