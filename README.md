# ZYVORA STREAMER License Website

Independent Ed25519 license issuer for software you own/control. It does NOT generate keys accepted by the original Devine/Pinkura developer's system.

## Requirements
- Node.js 18+
- A server/VPS for production

## Run locally
Linux/macOS:
```bash
export ADMIN_PASSWORD='Use-A-Long-Random-Password-Here'
node server.js
```
Windows PowerShell:
```powershell
$env:ADMIN_PASSWORD="Use-A-Long-Random-Password-Here"
node server.js
```
Open http://localhost:3000

## What it does
- Admin-password-protected license generator
- Issues lifetime license strings signed with Ed25519
- Optional device binding
- Public-key endpoint: `/api/public-key`
- Verification endpoint: `POST /api/verify` with `{ "license": "...", "deviceId": "..." }`
- Admin revocation endpoint: `POST /api/revoke` with `{ "licenseId": "..." }`

## Critical security notes
- Put this behind HTTPS before exposing it to the internet.
- Use a strong, unique `ADMIN_PASSWORD`.
- Back up `data/license-private.pem` securely. Never share or publish it.
- Your app/module must implement signature verification using the public key. A license generator alone cannot make an unrelated app accept these licenses.
- Do not put the private signing key in Android APKs, shell scripts, WebUI JavaScript, or any client-side code.
- Lifetime means no expiry; it does not mean impossible to revoke. The server keeps a revocation list.
