# frozen_string_literal: true

require "openssl"

module AgentAdmit
  ##
  # Verification for inbound AgentAdmit alert webhooks.
  #
  # AgentAdmit signs every alert webhook delivery with the app's webhook
  # signing secret (whsec_…, returned once when the webhook URL is
  # configured). The signature arrives in the X-AgentAdmit-Signature header:
  #
  #   X-AgentAdmit-Signature: t=<unix_ts>,v1=<hex hmac-sha256>
  #
  # where the HMAC input is "{t}.{raw_body}" keyed with the full whsec_
  # secret. Always verify against the raw request body (request.raw_post in
  # Rails), before any JSON parsing.
  #
  # @example Rails controller
  #   def alerts
  #     AgentAdmit::Webhook.verify_signature(
  #       request.raw_post,
  #       request.headers["X-AgentAdmit-Signature"].to_s,
  #       AgentAdmit.configuration.webhook_secret
  #     )
  #     event = JSON.parse(request.raw_post)
  #     # ...
  #   rescue AgentAdmit::WebhookSignatureError
  #     head :bad_request
  #   end
  #
  module Webhook
    # Header AgentAdmit signs alert webhook deliveries with.
    SIGNATURE_HEADER = "X-AgentAdmit-Signature"

    # Default maximum clock skew (seconds) allowed for replay protection.
    DEFAULT_TOLERANCE_SECONDS = 300

    module_function

    ##
    # Verify the X-AgentAdmit-Signature header on an inbound alert webhook.
    #
    # @param payload [String] the raw request body
    # @param header [String] the X-AgentAdmit-Signature header value
    # @param secret [String] the app's webhook signing secret (whsec_…)
    # @param tolerance [Integer] max clock skew in seconds (0 disables the check)
    # @param now [Integer, nil] override the current Unix timestamp (for tests)
    # @raise [WebhookSignatureError] if the header is missing/malformed, the
    #   timestamp is outside the tolerance window, or no signature matches;
    #   the message never includes the secret or the payload
    # @return [void]
    #
    def verify_signature(payload, header, secret, tolerance: DEFAULT_TOLERANCE_SECONDS, now: nil)
      raise WebhookSignatureError, "Webhook signing secret is required" if secret.nil? || secret.empty?
      raise WebhookSignatureError, "Missing X-AgentAdmit-Signature header" if header.nil? || header.empty?

      timestamp = nil
      candidates = []
      header.split(",").each do |part|
        key, _, value = part.strip.partition("=")
        case key
        when "t"
          raise WebhookSignatureError, "Malformed signature header" unless value.match?(/\A\d+\z/)

          timestamp = Integer(value)
        when "v1"
          candidates << value
        end
      end

      raise WebhookSignatureError, "Malformed signature header" if timestamp.nil? || candidates.empty?

      if tolerance.positive? && ((now || Time.now.to_i) - timestamp).abs > tolerance
        raise WebhookSignatureError, "Signature timestamp outside tolerance window"
      end

      expected = OpenSSL::HMAC.hexdigest("SHA256", secret, "#{timestamp}.#{payload}")
      matched = candidates.any? { |candidate| secure_compare(expected, candidate) }

      raise WebhookSignatureError, "Webhook signature verification failed" unless matched
    end

    ##
    # Boolean form of {verify_signature}.
    #
    # @return [Boolean]
    #
    def valid_signature?(payload, header, secret, tolerance: DEFAULT_TOLERANCE_SECONDS, now: nil)
      verify_signature(payload, header, secret, tolerance: tolerance, now: now)
      true
    rescue WebhookSignatureError
      false
    end

    ##
    # Constant-time string comparison (portable — OpenSSL.secure_compare is
    # not available on every openssl gem version).
    #
    # @api private
    #
    def secure_compare(expected, candidate)
      return false unless expected.bytesize == candidate.bytesize

      diff = 0
      expected_bytes = expected.unpack("C*")
      candidate.each_byte.with_index { |byte, i| diff |= byte ^ expected_bytes[i] }
      diff.zero?
    end
  end
end
