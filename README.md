# Security Dashboard - Cloudflare Pages + Hono.js

A full-stack security dashboard built with Hono.js, Cloudflare Pages Functions, and D1 database. Features session-based authentication, threat intelligence lookups from multiple providers, and API health monitoring.

## Features

- **Session-based Authentication**: Secure cookie-based sessions with HMAC signing
- **Profile Management**: User profile endpoint with demo data
- **Threat Intelligence Lookups**: Support for multiple providers:
  - VirusTotal (Very High Confidence) - IP, Domain, Hash
  - ThreatFox (High Confidence) - IP, Domain, Hash
  - OTX/LevelBlue (Medium Confidence) - IP, Domain, Hash
  - AbuseIPDB (High Confidence) - IP only
  - IBM X-Force (Medium Confidence) - IP, Domain, Hash
- **API Sandbox Health Checks**:
  - Outbound HTTP health checks
  - Internal D1 database health checks
- **Modern UI**: Tailwind CSS-based responsive interface

## Prerequisites

- Node.js 18+ and npm
- Cloudflare account
- Wrangler CLI

## Setup Instructions

### 1. Install Dependencies

```bash
npm install
```

### 2. Create D1 Database

Create a new D1 database for your project:

```bash
npx wrangler d1 create v1-db
```

This will output a database ID. Update `wrangler.toml` with your database ID:

```toml
[[d1_databases]]
binding = "DB"
database_name = "v1-db"
database_id = "your-actual-database-id"
```

### 3. Apply Database Schema

Initialize the database schema:

```bash
npx wrangler d1 execute v1-db --file=./database/schema.sql
```

For local development:

```bash
npx wrangler d1 execute v1-db --local --file=./database/schema.sql
```

### 4. Configure Environment Variables

#### Required Variables

- `SESSION_SECRET`: Secret key for signing session cookies (required)

#### Optional API Keys (for threat intelligence providers)

- `VT_API_KEY`: VirusTotal API key
- `THREATFOX_API_KEY`: ThreatFox API key (optional, public API available)
- `OTX_API_KEY`: AlienVault OTX API key
- `ABUSEIPDB_API_KEY`: AbuseIPDB API key
- `IBM_XF_API_KEY`: IBM X-Force API key (format: "apikey:password")

#### For Local Development

Create a `.dev.vars` file in the project root:

```bash
SESSION_SECRET=your-local-secret-key-min-32-chars
VT_API_KEY=your-virustotal-key
OTX_API_KEY=your-otx-key
ABUSEIPDB_API_KEY=your-abuseipdb-key
IBM_XF_API_KEY=apikey:password
```

#### For Production

Set environment variables in Cloudflare Pages dashboard:
1. Go to your Pages project
2. Navigate to Settings > Environment variables
3. Add the variables for Production and/or Preview environments

### 5. Run Development Server

Start the local development server:

```bash
npm run dev
```

The application will be available at `http://localhost:8788`

### 6. Deploy to Cloudflare Pages

#### First-time Deployment

```bash
npm run deploy
```

Follow the prompts to create a new Pages project or select an existing one.

#### Configure Pages Functions

After deploying, ensure your D1 database binding is configured:
1. Go to Cloudflare dashboard > Pages > Your project
2. Navigate to Settings > Functions
3. Add D1 database binding with name `DB`

#### Subsequent Deployments

Simply run:

```bash
npm run deploy
```

Or push to your connected Git repository if you've set up automatic deployments.

## Project Structure

```
.
├── functions/
│   ├── [[path]].ts          # Main Hono app with all routes
│   └── lib/
│       ├── session.ts        # Session management helper
│       └── providers.ts      # Threat intelligence provider clients
├── public/
│   ├── index.html           # Frontend HTML
│   └── app.js               # Frontend JavaScript
├── database/
│   └── schema.sql           # D1 database schema
├── wrangler.toml            # Cloudflare configuration
├── package.json             # Dependencies and scripts
└── tsconfig.json            # TypeScript configuration
```

## API Endpoints

### Authentication
- `POST /api/login` - Login with username
- `POST /api/logout` - Logout and clear session
- `GET /api/session` - Check current session status

### User
- `GET /api/profile` - Get user profile (requires authentication)

### Threat Intelligence
- `POST /api/threat-lookup` - Lookup IP, domain, or hash (requires authentication)
  - Body: `{ provider, type, value }`

### Health Checks
- `GET /api/health/outbound?target=URL` - Test outbound HTTP connectivity
- `GET /api/health/internal` - Check D1 database connectivity

## Usage

1. Open the application in your browser
2. Login with any username (demo mode)
3. Use the dashboard to:
   - View your profile
   - Perform threat intelligence lookups
   - Test API connectivity

## Development

### Type Checking

```bash
npm run typecheck
```

### Local Database

The development server uses a local D1 database instance. Data is stored in `.wrangler/state/v3/d1/`.

## Security Notes

- Session cookies are signed using HMAC-SHA256
- All authenticated endpoints require valid session
- API keys are stored as environment variables
- Cookies use httpOnly, secure, and sameSite flags

## License

MIT
