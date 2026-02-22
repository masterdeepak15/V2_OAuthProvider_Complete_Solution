# OAuth Provider V2 — Quick Start Guide

## What's New in V2

| Feature | V1 | V2 |
|---|---|---|
| Multi-tenancy | ❌ Single org | ✅ Multiple organizations |
| Organization signup | ❌ Manual seed | ✅ Self-service with OTP verification |
| User invitations | ❌ | ✅ Email invite + verification link |
| Email service | ❌ | ✅ Platform SMTP + per-org override |
| WAF | ❌ | ✅ Rate limiting, SQLi, XSS, IP blocking |
| Audit logs | Basic | ✅ Full session details (browser, OS, device, IP) |
| CORS origins | ❌ | ✅ Per-client allowed origins |
| Client secret view | ❌ Hidden forever | ✅ One-time reveal + regenerate |
| Super Admin | ❌ | ✅ Platform-level control panel |
| Health monitor | ❌ | ✅ Live dashboard with login chart |
| Data isolation | ❌ | ✅ Full org-level tenant isolation |

---

## Prerequisites

- [.NET 8 SDK](https://dotnet.microsoft.com/download)
- EF Core CLI: `dotnet tool install --global dotnet-ef`

---

## Step 1 — Setup & Run

```bash
cd OAuthProviderV2

# Restore packages
dotnet restore

# Trust the dev certificate (first time only)
dotnet dev-certs https --trust

# Apply database migrations (auto-runs on startup via DbSeeder.MigrateAsync)
# Or run manually:
dotnet ef migrations add InitialCreate
dotnet ef database update

# Start the server
dotnet run
```

Server starts at: **https://localhost:5000**

---

## Step 2 — First Login (Super Admin)

The seeder creates one built-in Super Admin:

| Field | Value |
|---|---|
| URL | https://localhost:5000/Account/Login |
| Email | `superadmin@oauthprovider.internal` |
| Password | `SuperAdmin@123456!` |

> ⚠️ **Change the password immediately** after first login in production.

The Super Admin has access to:
- `/super` — Platform overview dashboard
- `/super/organizations` — Block/unblock orgs, set limits
- `/super/waf` — WAF event monitor
- `/super/waf/rules` — Manage platform-wide firewall rules
- `/super/audits` — All audit logs across all orgs
- `/super/email` — Configure platform SMTP
- `/super/health` — Health and activity monitor

---

## Step 3 — Create an Organization

1. Open https://localhost:5000/Account/Signup
2. Fill in organization name, your admin details and a strong password
3. Click **Send Verification Code** — a 6-digit OTP is sent to your email
4. Enter the OTP to complete setup

> 💡 **No email server?** The OTP is also printed to the server console in Development mode. Look for the log line starting with `[Email]`.

---

## Step 4 — Org Admin Portal

After signup you land on https://localhost:5000/Account/Login. Sign in as the org owner.

### Create a Project
- Navigate to **Projects → + New Project**

### Register an OAuth Client
- Navigate to **OAuth Clients → + New Client**
- Select your project
- Fill in redirect URIs (e.g. `https://localhost:5001/auth/callback`)
- Add CORS origins if using a SPA (e.g. `https://localhost:5001`)
- Choose grant types and scopes
- Click **Create Client**

> ⚠️ The **Client Secret is shown only once** immediately after creation. Copy it and store it securely — it cannot be retrieved again. You can regenerate it from the client detail page if needed.

### Invite Users
- Navigate to **Users → + Invite User**
- Enter their email, name and role
- They receive a verification email with a link
- Until they click the link, they see **"Email Verification Pending"** when trying to log in
- If email isn't working, use the **📋 Get Link** button to copy their verification URL manually

---

## Step 5 — Connect Your Client App

Configure `OAuthClient/appsettings.json`:

```json
{
  "OAuthProvider": {
    "Authority": "https://localhost:5000",
    "ClientId": "client-XXXX",
    "ClientSecret": "your-raw-secret",
    "RedirectUri": "https://localhost:5001/auth/callback"
  }
}
```

Make sure the redirect URI matches **exactly** (same path, scheme, port) what you registered.

---

## Step 6 — Configure Email (Optional)

### Platform SMTP (Super Admin)
Go to `/super/email` and enter your SMTP credentials. This is the fallback for all orgs.

### Per-Org SMTP (Org Admin)
Go to `/settings/email`. Toggle off "Use platform default" and enter your own SMTP settings.

**Alert types you can toggle:**
- 🔐 Login alerts — email when a user signs in
- ⚠️ Security alerts — lockouts, suspicious activity  
- 🛡️ WAF alerts — critical firewall events

---

## Architecture

```
┌────────────────────────────────────────────────────────┐
│                    OAuth Provider V2                    │
├──────────────────┬─────────────────┬───────────────────┤
│  Static SSR      │  Blazor Server  │  MVC Controllers  │
│  Razor Pages     │  (Interactive)  │  (REST API)       │
│                  │                 │                   │
│  /Account/Login  │  Dashboard      │  /authorize       │
│  /Account/Signup │  Users          │  /token           │
│  /Account/Logout │  Clients        │  /userinfo        │
│  /Account/       │  Projects       │  /revoke          │
│    VerifyEmail   │  Tokens         │  /.well-known/    │
│                  │  Audit Logs     │   openid-config   │
│                  │  WAF Rules      │                   │
│                  │  Super Admin    │                   │
└──────────────────┴─────────────────┴───────────────────┘
           ↓                ↓
    ┌─────────────────────────────┐
    │   WAF Middleware (first)    │
    │   Rate Limit · SQLi · XSS  │
    │   Path Traversal · IP Block │
    └─────────────────────────────┘
           ↓
    ┌─────────────────────────────┐
    │       SQLite Database       │
    │   (swap to SQL Server via  │
    │    UseSqlServer() in       │
    │    Program.cs)             │
    └─────────────────────────────┘
```

### Data Isolation

Every Organization is a fully isolated tenant:
- All Projects, Clients, Tokens have `OrganizationId`
- Service methods enforce org-scoping before returning data
- Blocked orgs prevent login AND token issuance at the OAuth endpoint level
- Super Admin can see and manage all orgs but cannot impersonate

---

## WAF Features

The WAF middleware runs **before** all other middleware and blocks:

| Threat | Detection | Action |
|---|---|---|
| IP Block Rules | Database `WafRules` table | 403 |
| Suspicious User-Agents | Pattern match (sqlmap, nikto, nmap…) | 403 |
| Path Traversal | `../` and URL-encoded variants | 400 |
| SQL Injection | Keywords in query string | 400 |
| XSS | Script/event handler patterns in query string | 400 |
| Rate Limiting | Per-IP, per-endpoint sliding window | 429 |

Rate limits per endpoint:

| Endpoint | Limit | Window | Block Duration |
|---|---|---|---|
| `/Account/Login` | 10 req | 60s | 15 min |
| `/Account/Signup` | 5 req | 5 min | 1 hour |
| `/token` | 30 req | 60s | 5 min |
| All others | 200 req | 60s | 1 min |

Security headers added to every response:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: SAMEORIGIN`
- `X-XSS-Protection: 1; mode=block`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Content-Security-Policy: default-src 'self'; ...`

---

## Audit Log — Session Details Captured

Every audit event records:

| Field | Example |
|---|---|
| IP Address | `203.0.113.42` |
| Browser | `Chrome 122.0` |
| Operating System | `Windows 10.0` |
| Device Type | `Desktop` / `Mobile` / `Tablet` |
| Device Brand | `Apple`, `Samsung`… |
| User Agent | Full UA string |
| Event Type | `LoginSuccess`, `TokenIssued`… |
| Resource | `OAuthClient:42` |
| Failure Reason | `Invalid password` |

Click any row in the audit log table to expand full details.

---

## Troubleshooting

### Email / OTP not received
- Check server console — in Development the OTP is logged
- Configure SMTP at `/super/email` (Super Admin) or `/settings/email` (Org Admin)
- Use **📋 Get Link** in Users page to share the verification URL manually

### `redirect_uri_mismatch` error
Must match in 3 places exactly:
1. Client app `appsettings.json` → `RedirectUri`
2. OAuth Provider client registration → Redirect URIs list
3. Client app callback Razor Page `@page` directive

### Organization blocked
A Super Admin at `/super/organizations` must unblock it.

### Token expired immediately
Check `AccessTokenLifetimeSeconds` on the client — default is `3600` (1 hour).

### EF migration errors
```bash
dotnet ef migrations remove        # remove broken migration
dotnet ef migrations add InitialCreate
dotnet ef database update
```

Or delete `oauth_provider_v2.db` and let the app recreate on next startup.

---

## Production Checklist

- [ ] Change `Jwt:SigningKey` to a 64+ char random secret
- [ ] Change `Jwt:Issuer` to your real domain
- [ ] Switch SQLite to SQL Server: change `UseSqlite` → `UseSqlServer` in `Program.cs`
- [ ] Set `ASPNETCORE_ENVIRONMENT=Production`
- [ ] Configure platform SMTP at `/super/email`
- [ ] Change SuperAdmin default password
- [ ] Enable HTTPS with a real certificate
- [ ] Set `options.Cookie.SecurePolicy = CookieSecurePolicy.Always`
- [ ] Review and tighten CSP header in `WafMiddleware.cs`
- [ ] Use Azure Key Vault / AWS Secrets Manager for secrets
- [ ] Replace `EmailService.EncryptPassword` XOR with proper data protection
