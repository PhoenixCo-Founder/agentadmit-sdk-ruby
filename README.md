# AgentAdmit SDK for Ruby (Rails)

User-mediated AI agent authorization. Plug-and-play for any Rails app.

> **Get started:** Sign up at [agentadmit.com](https://agentadmit.com) -- Get your test keys -- Install the SDK -- Build.
> Test keys are available immediately after signup. Live keys become available when you subscribe an app.

## Quick Start

```ruby
# Gemfile
gem 'agentadmit'
```

```bash
bundle install
```

Add your credentials to `config/credentials.yml.enc` or `.env`:

```env
AGENTADMIT_APP_ID=app_yourappid
AGENTADMIT_API_KEY=aa_test_yourkey
```

Create an initializer at `config/initializers/agentadmit.rb`:

```ruby
AgentAdmit.configure do |config|
  # Defaults are read from ENV - nothing required here unless you need overrides.
end
```

Add scope enforcement to any controller:

```ruby
class OrdersController < ApplicationController
  before_action -> { require_scope_if_agent!('read:orders') }

  def index
    render json: current_user.orders
  end
end
```

The `require_scope_if_agent!` method is available in all controllers automatically
when you use Rails -- the Railtie includes `AgentAdmit::ScopeEnforcement` into
`ActionController::Base` on load.

Your app now supports AI agent connections with:
- Scoped access control (you define the scopes)
- User-controlled connection duration
- Token generation and exchange
- Mandatory introspection (every agent request validated through AgentAdmit)
- Revocation support via `tokens.revoke`

## How It Works

1. User clicks "AgentAdmit" in your app
2. Selects scopes and connection duration
3. Gets a token to give to their AI agent
4. Agent exchanges the token for scoped API access
5. User revokes anytime

The token goes to the human, not the agent. No automated delivery = no prompt injection surface.

## Important

**Mandatory introspection.** All token validation goes through api.agentadmit.com. There is no self-hosted mode. No local JWT validation. No bypass. This is required for security, audit logging, and scope enforcement.

**Embeddable admin panel.** Drop the `<AgentAdmitAdminPanel>` React component into your admin section to view all agent connections, usage metrics, billing status, and revoke any connection without leaving your app. See the React SDK for details.

**In-app AI scopes.** If your app has built-in AI features (analysis, plan generation, photo recognition), do not expose those as agent scopes. The user's AI agent can read the raw data and do the analysis itself. Exposing in-app AI endpoints to agents creates double cost.

### Consent Ledger (Caller-Identity Consent)

AgentAdmit can host per-user consent switches for three independent caller classes: `human_session`, `in_app_ai`, and `external_agent`. No class's setting implies another's.

**External agents:** the verify result already carries the verdict:

```ruby
result = AgentAdmit::IntrospectionClient.new.verify(token)
unless result.consent_granted?
  # the data owner has switched external agents off: return your own 403
end
```

**Human sessions and in-app AI** never hold AgentAdmit tokens, so ask directly:

```ruby
verdict = AgentAdmit::IntrospectionClient.new.check_consent(
  app_user_id: "user_8842", caller_class: "in_app_ai"
)
head :forbidden unless verdict["granted"]
```

Consent is orthogonal to revocation: a denied verdict means your app returns its own 403; the connection and token stay valid so the user can flip consent back on without re-connecting. Write switches through `PUT /api/v1/consent/settings` from your backend; export the audit trail with `GET /api/v1/consent/export` (every plan).

## Rate Limiting

The AgentAdmit introspection endpoint enforces rate limits. The Ruby SDK handles HTTP 429 responses **automatically** with exponential backoff and jitter -- no changes needed in your middleware code.

### Retry behavior

| Parameter | Default | Description |
|-----------|---------|-------------|
| Initial delay | 1 second | First retry wait |
| Backoff multiplier | 2x | Doubles each retry |
| Cap | 30 seconds | Maximum wait per retry |
| Jitter | 0-500 ms | Random addition to each delay |
| Max retries | **3** | Configurable |

The SDK also respects the `Retry-After` response header -- if present, it overrides the computed backoff delay.

### Configuring max retries

```ruby
AgentAdmit.configure do |config|
  config.max_retries = 5  # default: 3
end
```

Or via environment variable:

```env
AGENTADMIT_MAX_RETRIES=5
```

### Handling exhausted retries

When all retries are exhausted, `IntrospectionClient#verify` raises `AgentAdmit::RateLimitError`:

```ruby
begin
  result = client.verify(token)
rescue AgentAdmit::RateLimitError => e
  render json: { error: 'rate_limited', retry_after: e.retry_after }, status: 429
end
```

`RateLimitError` attributes:
- `retry_after` -- seconds from `Retry-After` header (`nil` if absent)
- `limit` -- `X-RateLimit-Limit` header value (`nil` if absent)
- `remaining` -- `X-RateLimit-Remaining` header value (`nil` if absent)
- `reset` -- `X-RateLimit-Reset` Unix timestamp (`nil` if absent)

## Documentation

Full integration guide: https://agentadmit.com/docs/app-owner-guide


## Data Collection & Privacy

The AgentAdmit Ruby SDK runs server-side and does not interact with app stores or end-user devices directly.

### What the SDK does
- Validates AgentAdmit tokens by calling AgentAdmit's hosted introspection endpoint (`https://api.agentadmit.com/api/v1/verify`) on every agent request -- this is mandatory introspection; there is no local or offline validation mode
- Enforces scope-based access control on your API routes
- Manages connection lifecycle (create, revoke) using the AgentAdmit hosted service

### What the SDK does NOT do
- Does not transmit raw end-user PII (such as name, email, or device identifiers) -- each introspection request sends the opaque access token and your API key
- Does not perform passive background telemetry or analytics -- network calls occur only during active token validation
- Does not maintain its own persistent local storage

### What the AgentAdmit hosted service records
On every token validation, AgentAdmit's `/api/v1/verify` endpoint receives the access token and API key, resolves the token to its `user_id`, `connection_id`, granted `scopes`, and `agent_label`, and records per-call metadata (including the endpoint and timestamp) for billing, audit logging, the security alerts engine, and usage metering. This is integral to how AgentAdmit works and applies to both test and live keys. See the "Mandatory introspection" notes above and the [compliance guide](https://agentadmit.com/docs/compliance) for the full data-handling description.

### Privacy impact
Since this SDK runs on your server, it has no direct App Store or Play Store compliance surface. Your client-side integration (e.g., the AgentAdmit React SDK) handles privacy manifest and data safety requirements.

For complete compliance guidance, see our [compliance guide](https://agentadmit.com/docs/compliance).

## License

All rights reserved. Patent pending.

## Security Alerts

```ruby
alerts = AgentAdmit::AlertsClient.new
```

Six alert type constants: `ALERT_TYPE_VOLUME_SPIKE`, `ALERT_TYPE_FAILED_SCOPE_ATTEMPTS`, `ALERT_TYPE_BURST_PATTERN`, `ALERT_TYPE_STALE_REACTIVATION`, `ALERT_TYPE_NEW_SCOPE_USAGE`, `ALERT_TYPE_REVOKED_CONNECTION_ATTEMPT`.

### Configure

```ruby
alerts.configure_alerts(
  app_id: 'app_abc123',
  alert_type: AgentAdmit::AlertsClient::ALERT_TYPE_VOLUME_SPIKE,
  enabled: true, threshold_value: 100, threshold_window_minutes: 5,
  kill_switch_enabled: true,
)
```

### List Events

```ruby
result = alerts.list_alerts(app_id: 'app_abc123', alert_type: AgentAdmit::AlertsClient::ALERT_TYPE_VOLUME_SPIKE)
```

### Get Config

```ruby
config = alerts.get_alert_config(app_id: 'app_abc123')
```


### Notifying Your Users

AgentAdmit detects anomalies, fires alerts, and (with kill switch) auto-revokes connections. **How you notify your own users is up to you.** AgentAdmit provides the data -- you deliver it through your own system (in-app notifications, email, push, etc.).

- **Poll alerts** -- Use the SDK methods above from your backend to check for new events, then notify users through your existing system.
- **Webhook delivery** -- Configure a webhook URL in your AgentAdmit dashboard. When an alert fires, AgentAdmit POSTs the payload to your server, signed with your `whsec_...` secret. Always verify the signature against the raw request body before trusting the payload:

  ```ruby
  # Rails controller
  def alerts
    AgentAdmit::Webhook.verify_signature(
      request.raw_post,
      request.headers["X-AgentAdmit-Signature"].to_s,
      AgentAdmit.configuration.webhook_secret # whsec_... from AGENTADMIT_WEBHOOK_SECRET
    )
    event = JSON.parse(request.raw_post)
    # ...
    head :ok
  rescue AgentAdmit::WebhookSignatureError
    head :bad_request
  end
  ```

  The header format is `t=<unix_ts>,v1=<hex>` -- an HMAC-SHA256 of `{t}.{raw_body}` keyed with your signing secret. Verification compares in constant time and rejects timestamps more than 5 minutes off (replay protection).
- **React SDK** -- Embed the `<AlertsPanel>` component so users can view their own alert history and tighten thresholds.

### Issuing & Exchanging Tokens

```ruby
tokens = AgentAdmit::TokensClient.new

# Duration is tri-state:
#   omit the argument          => AgentAdmit default (30 days)
#   nil                        => until the user revokes
#   Integer (60-31536000)      => explicit seconds
issued = tokens.issue_token(
  user_id: "user_42",
  scopes: ["read:orders"],
  role: "user",
  duration_seconds: nil # until revoked
)
connection_token = issued["token"] # ag_ct_...

# Agent side -- no API key needed; the connection token is the credential.
granted = tokens.exchange(connection_token, agent_label: "MyAssistant")

# Revoke when the user disconnects the agent.
tokens.revoke(granted["connection_id"], reason: "user_requested")
```
