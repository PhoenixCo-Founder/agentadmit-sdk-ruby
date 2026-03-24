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
AGENTADMIT_API_KEY=ak_test_yourkey
AGENTADMIT_SECRET=sk_test_yoursecret
```

Add scope enforcement to any controller:

```ruby
class OrdersController < ApplicationController
  before_action -> { agentadmit_require_scope!('read:orders') }

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

1. User clicks "AI Agent Access" in your app
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

## Documentation

Full integration guide: https://docs.agentadmit.com/getting-started

## License

All rights reserved. Patent pending.
