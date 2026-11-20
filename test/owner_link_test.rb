# frozen_string_literal: true

# SDK 1.15.0: confirm-each-time when the user has no passkey yet.
#
# Row A: confirmation["enrollment_required"] on the confirmation_required
# refusal is kept strictly (true/false only; anything else reads as absent) on
# the typed error and in the 403 body, and the agent is told the link alone
# cannot be used when it is true.
#
# Row B: TokensClient#create_owner_link posts to the hosted owner-link
# endpoint with the API key and returns a typed Hash, never a partial one.

require "minitest/autorun"
require "json"
require "stringio"
require "erb"
require_relative "../lib/agentadmit"

module OwnerLinkHelpers
  FakeResponse = Struct.new(:code, :headers, :body) do
    def [](name)
      headers[name]
    end
  end

  OLD_DESCRIPTION = "This action requires a fresh human confirmation. " \
                    "Give the confirmation link to the user, then retry with " \
                    "the X-AgentAdmit-Action-Attestation header."

  BASE = { "action_session_id" => "asess_abcdefghijklmnop",
           "action_session_url" => "https://agentadmit.com/confirm/action/asess_abcdefghijklmnop",
           "expires_at" => "2026-11-20T18:30:00Z", "scope" => "write:payments",
           "method" => "POST", "endpoint" => "/api/payments",
           "request_digest" => "sha256:deadbeef", "summary" => "Pay Alex $50" }.freeze

  ABSENT = Object.new.freeze

  def config
    cfg = AgentAdmit::Config.new
    cfg.app_id = "app_test"
    cfg.api_key = "aa_test_key"
    cfg.api_url = "https://api.agentadmit.test/"
    cfg
  end

  def fake_http(status, body, requests)
    response = FakeResponse.new(status.to_s, {}, body.is_a?(String) ? body : JSON.generate(body))
    http = Object.new
    http.define_singleton_method(:request) do |request|
      requests << request
      response
    end
    http
  end

  def confirmation_with(wire)
    c = BASE.dup
    c["enrollment_required"] = wire unless wire.equal?(ABSENT)
    c
  end

  def refusal(confirmation)
    { "active" => true, "error" => "confirmation_required", "confirmation" => confirmation }
  end

  def introspection_client(body)
    client = AgentAdmit::IntrospectionClient.new(config)
    http = fake_http(200, body, [])
    client.define_singleton_method(:build_http) { |_uri| http }
    client
  end

  # The 403 the Rack middleware sends for this verify answer.
  def middleware_403(body)
    AgentAdmit.configuration = config
    app = ->(_env) { raise "app must not run" }
    middleware = AgentAdmit::Middleware.new(app, scope_for: "write:payments")
    middleware.instance_variable_set(:@client, introspection_client(body))
    status, _headers, chunks = middleware.call(
      "HTTP_AUTHORIZATION" => "Bearer ag_at_dummy", "PATH_INFO" => "/api/payments",
      "REQUEST_METHOD" => "POST", "rack.input" => StringIO.new("{}")
    )
    [status, JSON.parse(chunks.first)]
  ensure
    AgentAdmit.configuration = nil
  end

  def typed_error(body)
    client = introspection_client(body)
    begin
      client.verify("ag_at_dummy", scope_used: "write:payments")
    rescue AgentAdmit::ActiveDenialError => e
      return e
    end
    raise "expected a refusal"
  end
end

class OwnerLinkRowATest < Minitest::Test
  include OwnerLinkHelpers

  [true, false].each do |wire|
    define_method("test_wire_#{wire}_is_kept_in_typed_copy_and_403_body") do
      error = typed_error(refusal(confirmation_with(wire)))
      assert_instance_of AgentAdmit::ConfirmationRequiredError, error
      assert_equal wire, error.confirmation["enrollment_required"]
      assert_equal wire, error.denial_body["confirmation"]["enrollment_required"]
      status, body = middleware_403(refusal(confirmation_with(wire)))
      assert_equal 403, status
      assert_equal wire, body["confirmation"]["enrollment_required"]
    end
  end

  { "absent" => ABSENT, "null" => nil, "string_true" => "true", "one" => 1, "zero" => 0,
    "object" => {}, "array" => [] }.each do |label, wire|
    define_method("test_wire_#{label}_is_treated_as_absent") do
      error = typed_error(refusal(confirmation_with(wire)))
      assert_instance_of AgentAdmit::ConfirmationRequiredError, error
      refute error.confirmation.key?("enrollment_required")
      assert_equal BASE, error.confirmation
      status, body = middleware_403(refusal(confirmation_with(wire)))
      assert_equal 403, status
      assert_equal BASE, body["confirmation"]
      refute body["confirmation"].key?("enrollment_required")
      assert_equal OLD_DESCRIPTION, body["error_description"]
    end
  end

  def test_block_missing_url_is_dropped_whole_even_with_enrollment_required
    c = confirmation_with(true)
    c.delete("action_session_url")
    error = typed_error(refusal(c))
    refute_instance_of AgentAdmit::ConfirmationRequiredError, error
    assert_equal "confirmation_required", error.code
    status, body = middleware_403(refusal(c))
    assert_equal 403, status
    refute body.key?("confirmation")
  end

  def test_sentence_only_when_true
    assert_equal "This action requires a fresh human confirmation, and this user has no passkey on file " \
                 "for the app yet, so the confirmation link alone cannot be used. Ask the user to open the " \
                 "request from inside the app. After they confirm, retry with the " \
                 "X-AgentAdmit-Action-Attestation header.",
                 AgentAdmit::ConfirmationRequiredError::ENROLLMENT_REQUIRED_DESCRIPTION
    _, body = middleware_403(refusal(confirmation_with(true)))
    assert_equal AgentAdmit::ConfirmationRequiredError::ENROLLMENT_REQUIRED_DESCRIPTION, body["error_description"]
    _, body = middleware_403(refusal(confirmation_with(false)))
    assert_equal OLD_DESCRIPTION, body["error_description"]
    _, body = middleware_403(refusal(confirmation_with(ABSENT)))
    assert_equal OLD_DESCRIPTION, body["error_description"]
  end

  def test_parser_alone_follows_the_matrix
    parse = ->(wire) { AgentAdmit::IntrospectionClient.parse_action_confirmation(confirmation_with(wire)) }
    assert_equal true, parse.call(true)["enrollment_required"]
    assert_equal false, parse.call(false)["enrollment_required"]
    [ABSENT, nil, "true", 1, 0, {}, []].each { |wire| refute parse.call(wire).key?("enrollment_required") }
  end
end

class OwnerLinkRowBTest < Minitest::Test
  include OwnerLinkHelpers

  ID = "asess_abc-DEF_ghijklmnop"
  OWNER_URL = "https://agentadmit.com/confirm/action/asess_abc-DEF_ghijklmnop#olt_secretsecret"

  def client(status, body, requests)
    c = AgentAdmit::TokensClient.new(config)
    http = fake_http(status, body, requests)
    c.define_singleton_method(:build_http) { |_uri| http }
    c
  end

  def created(extra = {})
    { "action_session_id" => ID, "owner_session_url" => OWNER_URL, "enrollment_required" => true,
      "enrollment_reason" => "no_passkey", "expires_at" => "2026-11-20T18:30:00Z" }.merge(extra)
  end

  def test_request_shape_and_201_result
    requests = []
    encoded = []
    c = client(201, created, requests)
    c.define_singleton_method(:path_segment) { |v| encoded << v; super(v) }
    link = c.create_owner_link(action_session_id: ID, app_user_id: "user_42")
    assert_equal [ID], encoded
    assert_equal 1, requests.size
    request = requests.first
    assert_instance_of Net::HTTP::Post, request
    assert_equal "/api/v1/action-sessions/#{ERB::Util.url_encode(ID)}/owner-link", request.path
    assert_equal "Bearer aa_test_key", request["Authorization"]
    assert_equal "application/json", request["Content-Type"]
    assert_equal({ "app_user_id" => "user_42" }, JSON.parse(request.body))
    assert_equal created, link
  end

  def test_id_is_url_encoded
    requests = []
    body = { "action_session_id" => "x", "owner_session_url" => "u", "enrollment_required" => false, "expires_at" => "e" }
    client(200, body, requests).create_owner_link(action_session_id: "asess_a/b?c#d e_ghijklmn", app_user_id: "user_42")
    assert_equal "/api/v1/action-sessions/asess_a%2Fb%3Fc%23d%20e_ghijklmn/owner-link", requests.first.path
  end

  def test_200_result_has_no_reason
    body = { "action_session_id" => ID, "owner_session_url" => "https://agentadmit.com/confirm/action/#{ID}",
             "enrollment_required" => false, "expires_at" => "2026-11-20T18:30:00Z" }
    link = client(200, body, []).create_owner_link(action_session_id: ID, app_user_id: "user_42")
    assert_equal false, link["enrollment_required"]
    refute link.key?("enrollment_reason")
  end

  [[401, "invalid_api_key"], [403, "api_key_not_app_linked"], [404, "not_found"], [409, "already_consumed"],
   [409, "already_verified"], [410, "session_expired"], [429, "rate_limited"], [500, "internal_error"]].each do |status, code|
    define_method("test_#{status}_#{code}_maps_to_api_error_without_retry") do
      requests = []
      error = assert_raises(AgentAdmit::ApiError) do
        client(status, { "error" => code }, requests).create_owner_link(action_session_id: ID, app_user_id: "user_42")
      end
      assert_kind_of AgentAdmit::IntrospectionError, error
      assert_equal status, error.status
      assert_equal code, error.code
      assert_equal 1, requests.size
    end
  end

  { "bad_prefix" => ["sess_abcdefghijklmnopqrst", "user_42"], "too_short" => ["asess_short", "user_42"],
    "not_a_string" => [42, "user_42"], "empty_user" => [ID, ""], "user_over_255" => [ID, "u" * 256],
    "user_nil" => [ID, nil] }.each do |label, (sid, user)|
    define_method("test_argument_error_#{label}_before_any_request") do
      requests = []
      assert_raises(ArgumentError) do
        client(201, created, requests).create_owner_link(action_session_id: sid, app_user_id: user)
      end
      assert_empty requests
    end
  end

  def test_255_character_user_id_is_accepted
    body = { "action_session_id" => ID, "owner_session_url" => "u", "enrollment_required" => false, "expires_at" => "e" }
    link = client(200, body, []).create_owner_link(action_session_id: ID, app_user_id: "u" * 255)
    assert_equal false, link["enrollment_required"]
  end

  { "no_url" => { "action_session_id" => ID, "enrollment_required" => true, "expires_at" => "e" },
    "url_not_string" => { "action_session_id" => ID, "owner_session_url" => 7, "enrollment_required" => true, "expires_at" => "e" },
    "no_flag" => { "action_session_id" => ID, "owner_session_url" => OWNER_URL, "expires_at" => "e" },
    "flag_string" => { "action_session_id" => ID, "owner_session_url" => OWNER_URL, "enrollment_required" => "true", "expires_at" => "e" },
    "flag_int" => { "action_session_id" => ID, "owner_session_url" => OWNER_URL, "enrollment_required" => 1, "expires_at" => "e" },
    "array" => [OWNER_URL],
    "not_json" => "not json #{OWNER_URL}" }.each do |label, body|
    define_method("test_malformed_2xx_#{label}_is_an_error_never_partial") do
      error = assert_raises(AgentAdmit::ApiError) do
        client(201, body, []).create_owner_link(action_session_id: ID, app_user_id: "user_42")
      end
      assert_match(/malformed/, error.message)
      assert_nil error.code
      refute_includes error.message, "olt_"
    end
  end

  def test_owner_link_is_never_logged
    out, err = capture_io do
      client(201, created, []).create_owner_link(action_session_id: ID, app_user_id: "user_42")
      error = assert_raises(AgentAdmit::ApiError) do
        client(201, created("enrollment_required" => nil), []).create_owner_link(action_session_id: ID, app_user_id: "user_42")
      end
      refute_includes error.message, "olt_"
    end
    refute_includes out, "olt_"
    refute_includes err, "olt_"
  end

  def test_network_failure_is_the_clients_introspection_error
    c = AgentAdmit::TokensClient.new(config)
    http = Object.new
    http.define_singleton_method(:request) { |_r| raise Errno::ECONNREFUSED }
    c.define_singleton_method(:build_http) { |_uri| http }
    error = assert_raises(AgentAdmit::IntrospectionError) do
      c.create_owner_link(action_session_id: ID, app_user_id: "user_42")
    end
    refute_kind_of AgentAdmit::ApiError, error
  end

  def test_not_mounted_on_middleware_or_routes
    lib = File.expand_path("../lib/agentadmit", __dir__)
    %w[middleware.rb scope_enforcement.rb railtie.rb caller_consent.rb].each do |file|
      refute_match(/owner.?link/i, File.read(File.join(lib, file), encoding: "UTF-8"), file)
    end
  end
end
