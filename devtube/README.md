# DevTube

A real full-stack developer video platform with YouTube search/playback, email authentication, optional Google/Microsoft/Apple OAuth, saved videos, and watch history.

## Run locally

1. Copy the environment file: `cp .env.example .env`
2. Create a YouTube Data API v3 key in Google Cloud and set `YOUTUBE_API_KEY`.
3. Start with Node 22.5+: `npm start`
4. Open `http://localhost:3000`

No npm install is required. The backend uses Node's built-in HTTP server and SQLite.

## Social login

Create OAuth apps with each provider and set the IDs/secrets in `.env`. Register these callbacks:

- Google: `http://localhost:3000/api/auth/callback/google`
- Microsoft: `http://localhost:3000/api/auth/callback/microsoft`
- Apple: `http://localhost:3000/api/auth/callback/apple`

For production, set `APP_ORIGIN` to the HTTPS domain and use matching callback URLs. Apple uses a Services ID and a generated client-secret JWT.

## Data

`devtube.db` is created automatically. Passwords are salted and hashed with scrypt. Sessions use random HttpOnly, SameSite cookies and only hashed tokens are stored.

## Important YouTube note

DevTube accesses public, embeddable YouTube videos through the official YouTube Data API. API quota and YouTube's terms apply; no third-party app can mirror or own “all” YouTube videos.
