# frozen_string_literal: true

require "time"

module AgentAdmit
  ##
  # App-attested presence: a ceremony fact your app attests at token issuance.
  #
  # Pass an instance to TokensClient#issue_token AFTER verifying and consuming
  # your app's own fresh, purpose-bound WebAuthn/passkey attestation for the
  # mint. The SDK forwards it to the hosted mint as
  # presence {verified: true, uv: true, method, verified_at}; the hosted
  # service stores it method-prefixed "app:<method>" — the provenance marker
  # that keeps app-attested facts distinct from hosted-witnessed ceremonies.
  #
  # Honesty ceiling: this is YOUR attestation, recorded and provenance-marked.
  # It is not witnessed by AgentAdmit and not independently verifiable. Only
  # construct one for a ceremony that verified the user with UV (biometric or
  # PIN user verification); verified/uv serialize as literal true and cannot
  # represent anything else — a ceremony without UV carries no presence fact,
  # so simply pass nil.
  #
  # verified_at must be recent: the hosted service enforces a 10-minute
  # freshness window with 60 seconds of future clock-skew slack. Ruby Time and
  # DateTime always carry an offset, so #iso8601 serializes RFC 3339 with an
  # explicit offset by construction (the hosted contract; offset-less
  # timestamps are rejected with 400).
  #
  class AppAttestedPresence
    METHOD_PATTERN = /\A[a-z0-9_]+\z/
    METHOD_MAX_LENGTH = 60

    # NOTE: a +method+ reader shadows Object#method on instances — the same
    # trade stdlib's Net::HTTPGenericRequest makes; the name matches the wire
    # field.
    attr_reader :method, :verified_at

    ##
    # @param method [String] your ceremony mechanism, 1-60 lowercase
    #   alphanumeric/underscore characters (e.g. "my_webauthn")
    # @param verified_at [Time, DateTime] when the ceremony completed
    # @raise [ArgumentError] when method is out of contract or verified_at is
    #   not a timestamp — validated at construction, before any request,
    #   where the fix is obvious
    #
    def initialize(method:, verified_at:)
      unless method.is_a?(String) && !method.empty? &&
             method.length <= METHOD_MAX_LENGTH && METHOD_PATTERN.match?(method)
        raise ArgumentError,
              "method must be 1-#{METHOD_MAX_LENGTH} lowercase alphanumeric/underscore " \
              "characters (e.g. 'my_webauthn')"
      end
      unless verified_at.respond_to?(:iso8601)
        raise ArgumentError,
              "verified_at must be a Time or DateTime (the ceremony that authorized " \
              "this mint just happened)"
      end

      @method = method
      @verified_at = verified_at
    end

    ##
    # The exact JSON object forwarded to the hosted mint.
    #
    # @return [Hash]
    #
    def to_wire
      {
        "verified" => true,
        "uv" => true,
        "method" => @method,
        "verified_at" => @verified_at.iso8601
      }
    end
  end
end
