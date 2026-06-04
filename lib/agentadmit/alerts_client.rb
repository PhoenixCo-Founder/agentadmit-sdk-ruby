# frozen_string_literal: true

require "net/http"
require "json"
require "uri"

module AgentAdmit
  ##
  # AlertsClient — configure and query security alerts via the AgentAdmit hosted service.
  #
  # Supported alert types:
  #   ALERT_TYPE_VOLUME_SPIKE, ALERT_TYPE_FAILED_SCOPE_ATTEMPTS,
  #   ALERT_TYPE_BURST_PATTERN, ALERT_TYPE_STALE_REACTIVATION,
  #   ALERT_TYPE_NEW_SCOPE_USAGE, ALERT_TYPE_REVOKED_CONNECTION_ATTEMPT
  #
  # @example
  #   client = AgentAdmit::AlertsClient.new
  #
  #   client.configure_alerts(
  #     app_id:                   "app_abc123",
  #     alert_type:               AgentAdmit::AlertsClient::ALERT_TYPE_VOLUME_SPIKE,
  #     enabled:                  true,
  #     threshold_value:          100,
  #     threshold_window_minutes: 5,
  #   )
  #
  class AlertsClient
    ALERT_TYPE_VOLUME_SPIKE               = "volume_spike"
    ALERT_TYPE_FAILED_SCOPE_ATTEMPTS      = "failed_scope_attempts"
    ALERT_TYPE_BURST_PATTERN              = "burst_pattern"
    ALERT_TYPE_STALE_REACTIVATION         = "stale_reactivation"
    ALERT_TYPE_NEW_SCOPE_USAGE            = "new_scope_usage"
    ALERT_TYPE_REVOKED_CONNECTION_ATTEMPT = "revoked_connection_attempt"

    def initialize(config = nil)
      @config = config || AgentAdmit.configuration || Config.new
    end

    ##
    # Configure alert thresholds for an app or connection.
    # POST /api/v1/alerts
    #
    # @param app_id [String]
    # @param alert_type [String] One of the ALERT_TYPE_* constants
    # @param connection_id [String, nil]
    # @param enabled [Boolean, nil]
    # @param threshold_value [Numeric, nil]
    # @param threshold_window_minutes [Integer, nil]
    # @param threshold_rate_per_minute [Numeric, nil]
    # @param stale_days [Integer, nil]
    # @param kill_switch_enabled [Boolean, nil]
    # @param kill_switch_threshold_value [Numeric, nil]
    # @param kill_switch_threshold_window_minutes [Integer, nil]
    # @return [Hash] { "ok" => true, "config" => {...} }
    # @raise [IntrospectionError]
    #
    def configure_alerts(
      app_id:,
      alert_type:,
      connection_id: nil,
      enabled: nil,
      threshold_value: nil,
      threshold_window_minutes: nil,
      threshold_rate_per_minute: nil,
      stale_days: nil,
      kill_switch_enabled: nil,
      kill_switch_threshold_value: nil,
      kill_switch_threshold_window_minutes: nil
    )
      body = { app_id: app_id, alert_type: alert_type }
      body[:connection_id]                        = connection_id                        unless connection_id.nil?
      body[:enabled]                              = enabled                              unless enabled.nil?
      body[:threshold_value]                      = threshold_value                      unless threshold_value.nil?
      body[:threshold_window_minutes]             = threshold_window_minutes             unless threshold_window_minutes.nil?
      body[:threshold_rate_per_minute]            = threshold_rate_per_minute            unless threshold_rate_per_minute.nil?
      body[:stale_days]                           = stale_days                           unless stale_days.nil?
      body[:kill_switch_enabled]                  = kill_switch_enabled                  unless kill_switch_enabled.nil?
      body[:kill_switch_threshold_value]          = kill_switch_threshold_value          unless kill_switch_threshold_value.nil?
      body[:kill_switch_threshold_window_minutes] = kill_switch_threshold_window_minutes unless kill_switch_threshold_window_minutes.nil?

      post_json("/api/v1/alerts", body)
    end

    ##
    # List alert events for an app.
    # GET /api/v1/alerts
    #
    # @param app_id [String]
    # @param connection_id [String, nil]
    # @param alert_type [String, nil]
    # @param limit [Integer] default 50
    # @param offset [Integer] default 0
    # @return [Hash] { "events" => [...], "total" => Integer, "limit" => Integer, "offset" => Integer }
    # @raise [IntrospectionError]
    #
    def list_alerts(app_id:, connection_id: nil, alert_type: nil, limit: 50, offset: 0)
      params = { app_id: app_id, limit: limit, offset: offset }
      params[:connection_id] = connection_id if connection_id
      params[:alert_type]    = alert_type    if alert_type

      get_json("/api/v1/alerts", params)
    end

    ##
    # Get the current alert configuration for an app.
    # GET /api/v1/alerts/config
    #
    # @param app_id [String]
    # @param connection_id [String, nil]
    # @return [Hash] { "app_id", "app_level", "connection_overrides", "alert_types" }
    # @raise [IntrospectionError]
    #
    def get_alert_config(app_id:, connection_id: nil)
      params = { app_id: app_id }
      params[:connection_id] = connection_id if connection_id

      get_json("/api/v1/alerts/config", params)
    end

    private

    def api_base
      base = @config.respond_to?(:api_url) ? @config.api_url : "https://api.agentadmit.com"
      base.to_s.chomp("/")
    end

    def auth_headers
      {
        "Authorization" => "Bearer #{@config.api_key}",
        "X-App-Id"      => @config.app_id.to_s,
        "Content-Type"  => "application/json",
      }
    end

    def post_json(path, body)
      uri  = URI.parse("#{api_base}#{path}")
      http = build_http(uri)
      req  = Net::HTTP::Post.new(uri.path)
      auth_headers.each { |k, v| req[k] = v }
      req.body = JSON.generate(body)

      response = http.request(req)
      check_status(response, "POST #{path}")
      JSON.parse(response.body)
    rescue IntrospectionError
      raise
    rescue StandardError => e
      raise IntrospectionError, "AgentAdmit alerts request failed: #{e.message}"
    end

    def get_json(path, params = {})
      query = URI.encode_www_form(params)
      uri   = URI.parse("#{api_base}#{path}?#{query}")
      http  = build_http(uri)
      req   = Net::HTTP::Get.new("#{uri.path}?#{uri.query}")
      auth_headers.each { |k, v| req[k] = v }

      response = http.request(req)
      check_status(response, "GET #{path}")
      JSON.parse(response.body)
    rescue IntrospectionError
      raise
    rescue StandardError => e
      raise IntrospectionError, "AgentAdmit alerts request failed: #{e.message}"
    end

    def build_http(uri)
      http              = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl      = uri.scheme == "https"
      http.read_timeout = 10
      http.open_timeout = 5
      http
    end

    def check_status(response, operation)
      status = response.code.to_i
      return if status < 400

      raise IntrospectionError,
        "AgentAdmit #{operation} failed with HTTP #{status}: #{response.body}"
    end
  end
end
