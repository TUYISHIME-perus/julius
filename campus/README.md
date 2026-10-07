# ESTG SDA church programs

## Run the site

Use Node.js 20.6 or newer. Add the administrator email and initial password to a local `.env` file (already excluded from version control); they are never included in the HTML:

```text
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=use-a-long-unique-password
```

Run `npm start` and open `http://localhost:3000`. A password change requires at least 12 characters. The first start and subsequent password changes save only a salted scrypt hash in `.admin-credentials.json`; keep that file private and backed up. The server still needs `ADMIN_EMAIL`, but after the first start the password can be removed from `.env` because the saved hash is used. If the credential file is lost, set `ADMIN_PASSWORD` again to initialize a new password.

The previous browser-side login values were publicly readable; choose a fresh password rather than reusing the old one.

For a public deployment, serve the site behind HTTPS and set `COOKIE_SECURE=true`. The server uses an HTTP-only, same-site session cookie and enforces access to the dashboard and preachers page. Do not host these pages with a static-only file server.

Passwords are hashed at rest and sent only to this server for verification. HTTPS protects them in transit, but a person controlling a signed-in browser can still inspect their own browser's submitted password in developer tools.
