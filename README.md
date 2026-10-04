# Chhatwan Hub Loyalty — full-stack starter

Premium black/yellow loyalty system for Chhatwan Hub.

## What is included

- Mobile-first glowing admin dashboard
- Permanent shop QR at `/join`
- First-time customer registration with name + WhatsApp + consent
- Same QR can be scanned again; a signed customer session identifies the customer on that device
- Server-side visit cooldown to stop rapid duplicate stamps
- Configurable visits required (1–100)
- Reward on/off + reward type + reward message
- Customer progress/stamp card
- Reward unlock + admin claim tracking
- Customer search by name/WhatsApp
- Full customer detail with visit history and reward history
- Admin manual visit button
- Google Review button
- Full JSON backup including customers, visits and rewards
- WhatsApp Cloud API template hook
- Expiring admin sessions
- Security headers + API rate limits
- SQLite persistence for normal Node hosting

## Run locally

1. Install Node.js 20+.
2. Copy `.env.example` to `.env`.
3. Set `ADMIN_PASSWORD`, `SESSION_SECRET`, and a public `BASE_URL` when deploying.
4. Run:

```bash
npm install
npm start
```

Local test: `http://localhost:3000/admin`
Customer page: `http://localhost:3000/join`

## Important production notes

- Do not paste passwords, API tokens or OTPs into chat. Put secrets in the hosting provider's environment variables.
- `BASE_URL` must be the real public HTTPS address before printing the permanent QR.
- WhatsApp notifications are not live until a Meta WhatsApp Cloud API setup and an approved template are configured in environment variables.
- SQLite is appropriate for a persistent Node server/VM. Do not use an ephemeral serverless filesystem for the database.
- The customer session is a signed bearer token stored on the customer's device. For stronger identity verification, add WhatsApp/SMS OTP before issuing the customer token.
- Review local privacy/consent requirements before collecting customer phone numbers.

## Docker

Build and run the app with a persistent volume so `loyalty.db` survives restarts:

```bash
docker build -t chhatwan-hub-loyalty .
docker run -d --name chhatwan-loyalty -p 3000:3000 --env-file .env -v chhatwan_data:/app chhatwan-hub-loyalty
```

For a real shop deployment, use your host's persistent disk/volume feature and HTTPS.
