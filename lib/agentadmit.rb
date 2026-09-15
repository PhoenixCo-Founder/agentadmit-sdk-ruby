# frozen_string_literal: true

require_relative "agentadmit/version"

module AgentAdmit
  class Error < StandardError; end

  ##
  # Raised when token validation fails. {#code} carries the machine-readable
  # reason from the API — one of VERIFY_ERROR_CODES (e.g. token_expired,
  # connection_expired, environment_mismatch); unknown codes pass through.
  #
  class InvalidTokenError < Error
    # @return [String] machine-readable error code
    attr_reader :code

    def initialize(message = "Invalid access token", code: "invalid_token")
      super(message)
      @code = code
    end
  end

  ##
  # Raised when the hosted /verify returns `active: true` together with a
  # string `error` field: the token itself is valid, but the authorization
  # service refused THIS call. Always a denial, never a pass-through --
  # middlewares map it to HTTP 403, and unknown error strings fail closed
  # (forward compatible: an error code this SDK version has never heard of
  # must never be treated as a pass).
  #
  # {#code} carries the machine-readable error string; {#data} carries the
  # parsed hosted response so denial responses can pass hosted fields
  # through; {#denial_body} is the ready-made 403 JSON body.
  #
  class ActiveDenialError < Error
    # @return [String] machine-readable error code from the active response
    attr_reader :code
    # @return [Hash] the parsed hosted introspection response
    attr_reader :data

    def initialize(message = "Call refused by the authorization service.",
                   code: "access_denied", data: {})
      super(message)
      @code = code
      @data = data
    end

    # The HTTP 403 body for this denial. Unknown codes get the generic
    # fail-closed shape; subclasses override with their contract shape.
    # @return [Hash]
    def denial_body
      { "error" => code,
        "error_description" => "Call refused by the authorization service." }
    end
  end

  ##
  # `active: true` + `error: "insufficient_scope"` -- token valid, the scope
  # this call enforces not granted. {#denial_body} is the spec step-up shape
  # (error, required_scope, granted_scopes).
  #
  class InsufficientScopeError < ActiveDenialError
    # @return [String, nil] the scope the call enforced (hosted value when
    #   present, else the scope_used this SDK sent)
    attr_reader :required_scope
    # @return [Array<String>, nil] granted scopes from the hosted response
    attr_reader :granted_scopes

    def initialize(message = "Scope not granted", required_scope: nil,
                   granted_scopes: nil, data: {})
      super(message, code: "insufficient_scope", data: data)
      @required_scope = required_scope
      @granted_scopes = granted_scopes
    end

    def denial_body
      { "error" => "insufficient_scope",
        "required_scope" => required_scope,
        "granted_scopes" => granted_scopes || [] }
    end
  end

  ##
  # `active: true` + `error: "bound_exceeded"` -- the hosted bounded-
  # capabilities layer refused the call. {#denial_body} passes the hosted
  # fields (error_description, bound, renewal) through verbatim.
  #
  class BoundExceededError < ActiveDenialError
    def initialize(message = "Call refused by the authorization service.", data: {})
      super(message, code: "bound_exceeded", data: data)
    end

    def denial_body
      body = { "error" => "bound_exceeded", "error_description" => message }
      body["bound"]   = data["bound"]   if data.key?("bound")
      body["renewal"] = data["renewal"] if data.key?("renewal")
      body
    end
  end

  ##
  # `active: true` + `error: "confirmation_required"` (SDK 1.11.0,
  # confirm-each-time) -- the scope IS granted, but THIS call needs a fresh
  # human confirmation before it may run. The hosted service has staged a
  # one-time ceremony for exactly this action; {#confirmation} is the
  # strictly-typed block describing it.
  #
  # The agent hands `confirmation["action_session_url"]` to the human. Only a
  # user-verified passkey on that hosted page produces an attestation; the
  # agent cannot complete the ceremony itself. The agent then retries the
  # SAME request with the header
  # `X-AgentAdmit-Action-Attestation: <action_session_id>`, which the SDK
  # forwards as `action_attestation_id` on the next verify.
  #
  # {#attestation_status} explains why a presented attestation was NOT
  # accepted, when one was presented (e.g. already_consumed, action_mismatch,
  # expired, not_confirmed).
  #
  # A malformed confirmation block never reaches this class: the client falls
  # back to a generic {ActiveDenialError} (fail closed, 403, no confirmation
  # block) rather than relaying an unusable ceremony.
  #
  class ConfirmationRequiredError < ActiveDenialError
    # The canonical agent-facing description. The hosted `error_description`
    # wins when the service sends one.
    DESCRIPTION = "This action requires a fresh human confirmation. " \
                  "Give the confirmation link to the user, then retry with " \
                  "the X-AgentAdmit-Action-Attestation header."

    # @return [Hash] the strictly-typed staged ceremony: action_session_id,
    #   action_session_url, expires_at, scope (Strings), and method, endpoint,
    #   request_digest, summary (String or nil).
    attr_reader :confirmation
    # @return [String, nil] why a presented attestation was not accepted.
    attr_reader :attestation_status

    def initialize(message = DESCRIPTION, confirmation:, attestation_status: nil, data: {})
      super(message, code: "confirmation_required", data: data)
      @confirmation = confirmation
      @attestation_status = attestation_status
    end

    # The 403 body: the refusal, the human-readable description, the staged
    # ceremony, and the hosted attestation diagnostics when present. Nothing
    # else from the wire -- a refusal must not leak identity or scope state.
    def denial_body
      body = { "error" => "confirmation_required",
               "error_description" => message,
               "confirmation" => confirmation }
      %w[attestation_status attestation_description renewal].each do |field|
        body[field] = data[field] if data[field].is_a?(String)
      end
      body
    end
  end

  class IntrospectionError < Error; end
  class ConfigurationError < Error; end

  ##
  # Raised when an inbound alert webhook fails X-AgentAdmit-Signature
  # verification.
  #
  class WebhookSignatureError < Error; end

  ##
  # Error codes /api/v1/verify returns with HTTP 200 and active: false
  # (insufficient_scope arrives with active: true — token valid, scope not
  # granted).
  #
  VERIFY_ERROR_CODES = %w[
    invalid_token
    token_expired
    token_revoked
    connection_revoked
    connection_expired
    environment_mismatch
    insufficient_scope
  ].freeze

  ##
  # Raised when the AgentAdmit introspection endpoint returns HTTP 429 and
  # all retry attempts (with exponential backoff + jitter) have been exhausted.
  #
  # @example
  #   begin
  #     client.verify(token)
  #   rescue AgentAdmit::RateLimitError => e
  #     render json: { error: 'rate_limited', retry_after: e.retry_after }, status: 429
  #   end
  #
  class RateLimitError < Error
    # @return [Float, nil] Seconds to wait before retrying (Retry-After header), or nil.
    attr_reader :retry_after
    # @return [Integer, nil] X-RateLimit-Limit value, or nil.
    attr_reader :limit
    # @return [Integer, nil] X-RateLimit-Remaining value, or nil.
    attr_reader :remaining
    # @return [Integer, nil] X-RateLimit-Reset Unix timestamp, or nil.
    attr_reader :reset

    def initialize(message = "AgentAdmit rate limit exceeded. Max retries exhausted.",
                   retry_after: nil, limit: nil, remaining: nil, reset: nil)
      super(message)
      @retry_after = retry_after
      @limit       = limit
      @remaining   = remaining
      @reset       = reset
    end
  end

  class << self
    attr_accessor :configuration

    def configure
      self.configuration ||= Config.new
      yield(configuration) if block_given?
    end
  end
end

require_relative "agentadmit/config"
require_relative "agentadmit/introspection_client"
require_relative "agentadmit/app_attested_presence"
require_relative "agentadmit/tokens_client"
require_relative "agentadmit/alerts_client"
require_relative "agentadmit/webhook"
require_relative "agentadmit/middleware"
require_relative "agentadmit/caller_consent"
# ScopeEnforcement is an ActiveSupport::Concern — only loadable inside Rails.
require_relative "agentadmit/scope_enforcement" if defined?(ActiveSupport)
require_relative "agentadmit/railtie" if defined?(Rails)
