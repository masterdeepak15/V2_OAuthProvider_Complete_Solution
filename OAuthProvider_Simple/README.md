# OAuth Provider — ASP.NET Core Blazor Server

A complete, custom OAuth 2.0 Authorization Server built with ASP.NET Core Blazor Server (.NET 8), Entity Framework Core (SQLite), and ASP.NET Core Identity. **No JavaScript. No external OAuth libraries.**

---

## 🏗 Architecture

```
OAuthProvider/
├── Components/
│   ├── App.razor                    # Root HTML shell
│   ├── Routes.razor                 # Router with auth guard
│   ├── _Imports.razor
│   ├── Layout/
│   │   ├── MainLayout.razor         # Dashboard sidebar layout
│   │   └── AuthLayout.razor         # Minimal layout for login
│   ├── Pages/
│   │   ├── Dashboard.razor          # Overview with stats
│   │   ├── Projects.razor           # Project list/create
│   │   ├── ProjectDetail.razor      # Project members & clients
│   │   ├── Clients.razor            # All clients list
│   │   ├── ClientCreate.razor       # New client wizard
│   │   ├── ClientDetail.razor       # Edit client, manage tokens
│   │   ├── Users.razor              # User management
│   │   ├── UserDetail.razor         # User roles & history
│   │   ├── Tokens.razor             # Active token monitor
│   │   ├── Docs.razor               # API documentation
│   │   └── Login.razor              # Authentication page
│   └── Shared/
│       └── RedirectToLogin.razor
├── Controllers/
│   ├── OAuthController.cs           # /authorize, /token, /userinfo, /revoke
│   └── AccountController.cs         # /Account/Logout
├── Data/
│   ├── ApplicationDbContext.cs      # EF Core DbContext (Fluent API)
│   └── DbSeeder.cs                  # Seed admin + sample data
├── Models/
│   ├── ApplicationUser.cs           # Extends IdentityUser
│   └── DomainModels.cs              # All OAuth domain models
├── Services/
│   ├── JwtService.cs                # JWT generation & validation
│   ├── OAuthService.cs              # OAuth flows implementation
│   ├── DashboardService.cs          # Admin dashboard data service
│   └── IdentityRevalidatingAuthenticationStateProvider.cs
├── wwwroot/
│   └── app.css                      # Custom styles (Bootstrap extended)
├── Program.cs                       # DI container & middleware pipeline
├── appsettings.json
└── OAuthProvider.csproj
```

---

## 🚀 Quick Start

### Prerequisites
- .NET 8 SDK: https://dotnet.microsoft.com/download
- No other dependencies needed

### 1. Clone / extract the project

```bash
cd OAuthProvider
```

### 2. Restore packages

```bash
dotnet restore
```

### 3. Create database migrations

```bash
dotnet ef migrations add InitialCreate
dotnet ef database update
```

> **Note:** The database will be automatically created and seeded on first run if you skip migration creation — `MigrateAsync()` is called in `DbSeeder`.

### 4. Run the application

```bash
dotnet run
```

Open https://localhost:5000 (or the URL shown in console).

### 5. Default credentials

| Field    | Value                        |
|----------|------------------------------|
| Email    | admin@oauthprovider.dev      |
| Password | Admin@123456!                |

The seeded **Client ID** and **Client Secret** are printed to console on first run.

---

## 🔐 OAuth 2.0 Endpoints

| Endpoint                              | Method | Description                        |
|---------------------------------------|--------|------------------------------------|
| `/.well-known/openid-configuration`   | GET    | Discovery document                 |
| `/authorize`                          | GET    | Authorization Code flow            |
| `/token`                              | POST   | Exchange code / refresh token      |
| `/userinfo`                           | GET    | Authenticated user info (Bearer)   |
| `/revoke`                             | POST   | Revoke a token                     |

### Authorization Code Flow

```
1. GET /authorize?response_type=code
                 &client_id=YOUR_CLIENT_ID
                 &redirect_uri=https://yourapp.com/callback
                 &scope=openid+profile
                 &state=RANDOM_STATE

2. User authenticates → redirected to redirect_uri?code=AUTH_CODE&state=...

3. POST /token
   grant_type=authorization_code
   &code=AUTH_CODE
   &redirect_uri=https://yourapp.com/callback
   &client_id=YOUR_CLIENT_ID
   &client_secret=YOUR_SECRET

4. Response: { access_token, refresh_token, expires_in, token_type }
```

### PKCE Support (Recommended)

```
code_challenge_method=S256
code_challenge=BASE64URL(SHA256(code_verifier))
```

### Client Credentials Flow

```
POST /token
grant_type=client_credentials
&client_id=YOUR_CLIENT_ID
&client_secret=YOUR_SECRET
```

---

## 📋 Admin Dashboard Features

### 1️⃣ Overview
- Stats cards: Total Users, Projects, Clients, Active Tokens
- Recent login activity table

### 2️⃣ Projects (`/projects`)
- Create / delete projects
- View all clients per project
- Assign users to projects with roles

### 3️⃣ OAuth Clients (`/clients`)
- Create new clients with configurable:
  - Redirect URIs
  - Allowed scopes
  - Grant types
  - Token lifetimes
- Regenerate client secrets
- Enable / disable clients
- View & revoke issued tokens

### 4️⃣ Users (`/users`)
- Create users with email/password
- Assign roles (Admin / Developer)
- Lock / unlock accounts
- View login history

### 5️⃣ Token Monitor (`/tokens`)
- View all active access tokens
- See user, scopes, expiry
- Revoke individual tokens

---

## 🗄 Database Models

```
ApplicationUser         — extends IdentityUser
  ├── FirstName, LastName, IsActive, LastLoginAt
  ├── ProjectUsers[]
  └── LoginAudits[]

Project
  ├── Name, Description, IsActive
  ├── Clients[]
  └── ProjectUsers[]

OAuthClient
  ├── ClientId (unique), ClientSecretHash
  ├── RedirectUris[], AllowedScopes[], AllowedGrantTypes[]
  ├── AccessTokenLifetimeSeconds, RefreshTokenLifetimeDays
  ├── AccessTokens[], RefreshTokens[]
  └── AuthorizationCodes[]

AuthorizationCode       — 10 minute expiry, single use, PKCE support
AccessToken             — JWT, stored for revocation
RefreshToken            — Opaque token, rotated on use
LoginAudit              — IP, UserAgent, success/failure
```

---

## 🔒 Security Features

- ✅ Client secrets **BCrypt hashed** (never stored plain)
- ✅ JWT tokens signed with **HMAC-SHA256**
- ✅ Refresh token **rotation** (old token revoked on use)
- ✅ Authorization codes are **single-use, 10-minute expiry**
- ✅ **PKCE** support (S256 and plain)
- ✅ **Redirect URI validation** (exact match against registered URIs)
- ✅ Account **lockout** after 5 failed attempts (15 min)
- ✅ **CSRF protection** on all forms (Blazor AntiforgeryToken)
- ✅ Secure **HttpOnly cookies** with SlidingExpiration
- ✅ **HTTPS enforced** in production (HSTS enabled)
- ✅ **Zero JavaScript** — fully Blazor Server-Side

---

## 🔧 Switching to SQL Server

In `Program.cs`, replace the SQLite configuration:

```csharp
// SQLite (default):
options.UseSqlite(connectionString, b => b.MigrationsAssembly(...))

// SQL Server:
options.UseSqlServer(connectionString)
```

In `appsettings.json`:
```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=.;Database=OAuthProvider;Trusted_Connection=True;"
  }
}
```

Then re-run migrations:
```bash
dotnet ef migrations add InitialCreate
dotnet ef database update
```

---

## ⚙ Configuration

| Setting                  | Description                         | Default                |
|--------------------------|-------------------------------------|------------------------|
| `Jwt:Issuer`             | JWT issuer claim                    | https://localhost:5000 |
| `Jwt:SigningKey`         | **Change this in production!**      | (32+ char string)      |
| `ConnectionStrings:DefaultConnection` | Database path           | oauth_provider.db      |

> **Production:** Store `Jwt:SigningKey` in environment variables or Azure Key Vault, not in appsettings.json.

---

## 🏃 Migration Commands Reference

```bash
# Add initial migration
dotnet ef migrations add InitialCreate

# Apply migrations to database
dotnet ef database update

# Roll back to specific migration
dotnet ef database update PreviousMigrationName

# Remove last unapplied migration
dotnet ef migrations remove

# Generate SQL script (for production deployment)
dotnet ef migrations script --output migration.sql
```

---

## 🧱 Role-Based Authorization

| Role      | Access                                              |
|-----------|-----------------------------------------------------|
| Admin     | Full dashboard access (all pages)                   |
| Developer | API docs, view own clients                          |

Pages use `[Authorize(Roles = "Admin")]` attributes.

---

## 📦 NuGet Packages

| Package                                             | Purpose                        |
|-----------------------------------------------------|--------------------------------|
| Microsoft.AspNetCore.Identity.EntityFrameworkCore   | Identity + EF Core             |
| Microsoft.EntityFrameworkCore.Sqlite                | SQLite provider                |
| Microsoft.EntityFrameworkCore.Tools                 | Migrations CLI                 |
| Microsoft.AspNetCore.Authentication.JwtBearer       | JWT middleware                 |
| System.IdentityModel.Tokens.Jwt                     | JWT creation                   |
| BCrypt.Net-Next                                     | Password hashing               |
