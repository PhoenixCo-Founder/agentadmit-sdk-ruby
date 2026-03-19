# frozen_string_literal: true

require "net/http"
require "json"
require "uri"

module AgentAdmit
  ##
  # Mandatory introspection client — validates tokens via AgentAdmit hosted service.
  # No local JWT decode. Every verification call goes through AgentAdmit.
  #
  class IntrospectionClient
    IntrospectionResult = Struct.new(:user_id, :connection_id, :scopes, :agent_label, keyword_init: true) do
      def has_scope?(scope)
        scopes.include?(scope)
      end
    end

    def initialize(config = nil)
      @config = config || AgentAdmit.configuration || Config.new
    end

    ##
    # Validate an ag_at_ token via introspection.
    #
    # @param token [String] The full token including ag_at_ prefix
    # @return [IntrospectionResult]
    # @raise [InvalidTokenError] if validation fails
    # @raise [IntrospectionError] if the service is unreachable
    #
    def verify(token)
      unless token.start_with?(@config.token_prefix_access)
        raise InvalidTokenError, "Not an AgentAdmit access token"
      end

      uri = URI.parse(@config.verify_url)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == "https"
      http.read_timeout = 5
      http.open_timeout = 5

      request = Net::HTTP::Post.new(uri.path)
      request["Authorization"] = "Bearer #{token}"
      request["X-App-Id"] = @config.app_id
      request["X-Api-Key"] = @config.api_key
      request["Content-Type"] = "application/json"

      begin
        response = http.request(request)
      rescue StandardError => e
        raise IntrospectionError, "Introspection failed: #{e.message}"
      end

      case response.code.to_i
      when 200
        data = JSON.parse(response.body)
        raise InvalidTokenError, "Introspection returned no user" if data["user_id"].nil?

        IntrospectionResult.new(
          user_id: data["user_id"],
          connection_id: data["connection_id"],
          scopes: data["scopes"] || [],
          agent_label: data["agent_label"] || "Unknown Agent"
        )
      when 401
        data = JSON.parse(response.body) rescue {}
        raise InvalidTokenError, data["error_description"] || "Token validation failed"
      else
        raise IntrospectionError, "Verification service returned #{response.code}"
      end
    end
  end
end
