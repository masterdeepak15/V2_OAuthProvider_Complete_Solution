# OAuth Client Demo App — ASP.NET Core Blazor Server

A complete demo client application that authenticates users via your custom OAuth Provider
using **Authorization Code Flow + PKCE**. No passwords stored here — credentials live only
on the OAuth Provider.

---

## 📁 Project Structure

```
OAuthClient/
├── Components/
│   ├── App.razor                     # Root HTML with @rendermode="@InteractiveServer"
│   ├── Routes.razor                  # Router + auth guard
│   ├── _Imports.razor
│   ├── Layout/
│   │   └── MainLayout.razor          # Navbar with sign-in/out
│   └── Pages/
│       ├── Home.razor                # Public landing page
│       ├── Profile.razor             # /profile — shows /userinfo claims + token status
│       └── DashboardPage.razor       # /dashboard — protected, shows cookie claims + flow
├── Pages/
│   └── Account/
│       ├── Login.cshtml / .cs        # Static SSR: builds authorize URL, redirects
│       ├── Callback.cshtml / .cs     # Static SSR: exchanges code, writes cookie
│       └── Logout.cshtml / .cs       # Static SSR: revokes token, clears cookie
├── Services/
│   ├── OAuthFlowService.cs           # HTTP calls to provider (/token, /userinfo, /revoke)
│   ├── PkceService.cs                # Generates code_verifier + code_challenge (S256)
│   ├── TokenStore.cs                 # Server-side token cache (never goes to browser)
│   └── ServerSideAuthenticationStateProvider.cs
├── Models/
│   └── OAuthModels.cs                # OAuthSettings, UserProfile, TokenResponse
├── wwwroot/app.css
├── appsettings.json
└── Program.cs
```

---

## 🚀 Quick Setup

### Step 1 — Start the OAuth Provider

```bash
cd OAuthProvider
dotnet run
# Runs on https://localhost:5000
```

On first run, it prints the seeded **Client ID** and **Client Secret** to the console.

---

### Step 2 — Register the client (if not seeded)

Open the Admin Console at **https://localhost:5000** and log in with:
- Email: `admin@oauthprovider.dev`
- Password: `Admin@123456!`

Go to **OAuth Clients → Create New Client** and fill in:

| Field            | Value                                    |
|------------------|------------------------------------------|
| Project          | Sample Project (or create a new one)     |
| Name             | Demo Client App                          |
| Redirect URI     | `https://localhost:5001/auth/callback`   |
| Scopes           | ✅ openid  ✅ profile  ✅ email           |
| Grant Types      | ✅ authorization_code  ✅ refresh_token  |

**Save the Client ID and Client Secret shown after creation.**

---

### Step 3 — Configure the client app

Edit `OAuthClient/appsettings.json`:

```json
{
  "OAuthProvider": {
    "BaseUrl": "https://localhost:5000",
    "ClientId": "PASTE_YOUR_CLIENT_ID_HERE",
    "ClientSecret": "PASTE_YOUR_CLIENT_SECRET_HERE",
    "RedirectUri": "https://localhost:5001/auth/callback",
    "Scopes": "openid profile email"
  }
}
```

---

### Step 4 — Run the client app

```bash
cd OAuthClient
dotnet run
# Runs on https://localhost:5001
```

Open **https://localhost:5001** and click **Sign In with OAuth Provider**.

---

## 🔐 How Authentication Works

```
Browser (https://localhost:5001)          OAuth Provider (https://localhost:5000)
─────────────────────────────────          ────────────────────────────────────────

1. GET /Account/Login
   ├── POST /Account/Login (form submit)
   │   ├── Generate state + PKCE pair
   │   ├── Store { state → verifier } in IMemoryCache (10 min TTL)
   │   └── 302 → /authorize?response_type=code
   │               &client_id=...
   │               &redirect_uri=https://localhost:5001/auth/callback
   │               &scope=openid profile email
   │               &state=<random>
   │               &code_challenge=<SHA256(verifier)>
   │               &code_challenge_method=S256
   │
2.                                         ← User sees login page
                                           ← User enters credentials
                                           ← Provider validates, creates auth code
                                           → 302 /auth/callback?code=XXX&state=YYY
   │
3. GET /auth/callback?code=XXX&state=YYY
   ├── Look up verifier from cache using state ← (CSRF validated here)
   ├── POST /token { grant_type=authorization_code, code, code_verifier, ... }
   │                                          ← Provider verifies PKCE, returns tokens
   ├── GET /userinfo (Bearer access_token)   ← Provider returns { sub, email, name, ... }
   ├── Store { sessionId → AccessToken, RefreshToken } in ITokenStore (server-side)
   ├── Build ClaimsPrincipal from userinfo claims
   └── HttpContext.SignInAsync() → Set-Cookie: .DemoApp.Auth=...
   │
4. 302 → / (or original ReturnUrl)
   Browser now has session cookie (HttpOnly, Secure, SameSite=Lax)
   Tokens are NEVER sent to the browser.
```

---

## 🔑 Key Design Decisions

### Why Login/Callback/Logout are Razor Pages (not Blazor)

`HttpContext.SignInAsync()` writes a `Set-Cookie` response header. In Blazor Server,
the HTTP response has already been flushed when the WebSocket circuit opens — so any
call to `SignInAsync` inside a Blazor component is silently ignored. Razor Pages run as
static SSR (before Blazor takes over), so they can write cookies correctly.

### Why tokens are stored server-side

Access tokens are JWTs that grant API access. Storing them in the browser (localStorage,
cookies) exposes them to XSS. Instead, this app:
- Stores tokens in `ITokenStore` (in-memory dictionary, server-side)
- Gives the browser only a session ID inside the `ClaimsPrincipal`
- Looks up the token server-side whenever it needs to call the provider

**For production:** Replace `InMemoryTokenStore` with a Redis-backed `IDistributedCache`.

### PKCE (Proof Key for Code Exchange)

Prevents authorization code interception attacks:
1. App generates a random `code_verifier` (64 bytes, base64url-encoded)
2. App computes `code_challenge = BASE64URL(SHA256(code_verifier))`
3. Sends `code_challenge` to provider in `/authorize`
4. Sends `code_verifier` to provider in `/token`
5. Provider recomputes the challenge and verifies — only the original app can exchange the code

---

## 📄 Pages

| URL | Auth Required | Description |
|-----|---------------|-------------|
| `/` | ❌ Public | Landing page with sign-in button |
| `/Account/Login` | ❌ Public | Redirect to OAuth Provider |
| `/auth/callback` | ❌ Public | Handles OAuth callback (Razor Page) |
| `/Account/Logout` | ❌ POST only | Sign out + revoke token |
| `/profile` | ✅ Required | User profile from /userinfo |
| `/dashboard` | ✅ Required | Cookie claims, token status, flow diagram |

---

## ⚙ Configuration Reference

| Key | Description |
|-----|-------------|
| `OAuthProvider:BaseUrl` | URL of the OAuth Provider (`https://localhost:5000`) |
| `OAuthProvider:ClientId` | Client ID from the provider admin console |
| `OAuthProvider:ClientSecret` | Client secret (keep this safe!) |
| `OAuthProvider:RedirectUri` | Must exactly match what's registered on the provider |
| `OAuthProvider:Scopes` | Space-separated scopes to request |

---

## 🔧 Running Both Apps Together

```bash
# Terminal 1 — OAuth Provider (port 5000)
cd OAuthProvider && dotnet run

# Terminal 2 — Client App (port 5001)
cd OAuthClient && dotnet run

# Then open: https://localhost:5001
```

Both use self-signed dev certs. Run `dotnet dev-certs https --trust` once if you get
certificate errors.
