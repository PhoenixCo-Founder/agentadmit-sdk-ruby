# AgentAdmit SDK for Ruby (Rails)

User-mediated AI agent authorization. Plug-and-play for any Rails app.

## Quick Start

```ruby
# Gemfile
gem 'agentadmit'
```

```bash
bundle install
rails generate agentadmit:install
```

Add your credentials to `config/credentials.yml.enc` or `.env`:

```env
AGENTADMIT_APP_ID=app_yourappid
AGENTADMIT_API_KEY=aa_test_yourkey
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

Your app now supports AI agent connections with:
- Scoped access control (you define the scopes)
- User-controlled connection duration
- Token generation and exchange
- Mandatory introspection (every agent request validated through AgentAdmit)
- Revocation and audit logging
- Discovery endpoint at `/.well-known/agentadmit`

## How It Works

1. User clicks "AgentAdmit" in your app
2. Selects scopes and connection duration
3. Gets a token to give to their AI agent
4. Agent exchanges the token for scoped API access
5. User revokes anytime

The token goes to the human, not the agent. No automated delivery = no prompt injection surface.

## Important

**Mandatory introspection.** All token validation goes through api.agentadmit.com. There is no self-hosted mode. No local JWT validation. No bypass. This is required for security, audit logging, and scope enforcement.

**Admin revocation.** As the app operator, you can revoke any user's agent connection via `DELETE /agentadmit/admin/connections/{connection_id}` (requires admin role or `manage:connections` scope).

**Embeddable admin panel.** Drop the `<AgentAdmitAdminPanel>` React component into your admin section to view all agent connections, usage metrics, billing status, and revoke any connection without leaving your app. See the React SDK for details.

**In-app AI scopes.** If your app has built-in AI features (analysis, plan generation, photo recognition), do not expose those as agent scopes. The user's AI agent can read the raw data and do the analysis itself. Exposing in-app AI endpoints to agents creates double cost.

## Rate Limiting

The AgentAdmit introspection endpoint enforces rate limits. The Ruby SDK handles HTTP 429 responses **automatically** with exponential backoff and jitter — no changes needed in your middleware code.

### Retry behavior

| Parameter | Default | Description |
|-----------|---------|-------------|
| Initial delay | 1 second | First retry wait |
| Backoff multiplier | 2× | Doubles each retry |
| Cap | 30 seconds | Maximum wait per retry |
| Jitter | 0–500 ms | Random addition to each delay |
| Max retries | **3** | Configurable |

The SDK also respects the `Retry-After` response header — if present, it overrides the computed backoff delay.

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
- `retry_after` — seconds from `Retry-After` header (`nil` if absent)
- `limit` — `X-RateLimit-Limit` header value (`nil` if absent)
- `remaining` — `X-RateLimit-Remaining` header value (`nil` if absent)
- `reset` — `X-RateLimit-Reset` Unix timestamp (`nil` if absent)

## Documentation

Full integration guide: https://agentadmit.com/docs/app-owner-guide


## Data Collection & Privacy

The AgentAdmit Ruby SDK runs server-side and does not interact with app stores or end-user devices directly.

### What the SDK does
- Validates AgentAdmit tokens presented by AI agents
- Enforces scope-based access control on your API routes
- Manages connection lifecycle (create, revoke, audit)

### What the SDK does NOT do
- Does not collect end-user data
- Does not send telemetry or analytics
- Does not phone home to AgentAdmit servers (all operations use your configured keys and storage)
- Does not track users or devices

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
