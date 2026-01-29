# Threat Model — Secure Notes

## Assets
- User credentials (password hashes)
- Session cookies / auth state
- Notes data (confidentiality + integrity)
- Server environment secrets (session secret, DB path)

## Entry Points
- /register
- /login
- /logout
- /notes (CRUD endpoints)

## Trust Boundaries
- Browser ↔ Server (untrusted network)
- Server ↔ Database
- Server ↔ Environment/Secrets

## Top Threats (STRIDE)
- Spoofing: session hijack, weak auth
- Tampering: injection altering DB
- Repudiation: lack of audit logs
- Information disclosure: IDOR exposes other users’ notes
- Denial of service: abusive requests
- Elevation of privilege: access control bugs

