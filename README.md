# CertiChain (static, client-side)

CertiChain is a tamper-evident certificate issuance and verification
tool. Every certificate is hashed (SHA-256) and appended to a simple
hash chain ("ledger"), similar in spirit to a blockchain. Certificates
carry a QR code encoding their ID and hash, so anyone with a phone
camera can verify a printed certificate on the spot.

This version is **100% static HTML/CSS/JS — no backend, no build
step, no dependencies to install.** It runs entirely in the browser
and stores its data in that browser's `localStorage`.

## Project structure

```
certichain-web/
├── index.html
├── css/
│   └── app.css
├── js/
│   └── app.js
├── .gitignore
└── README.md
```

## Run it

**Option A — just open the file.** Double-click `index.html`. Modern
browsers treat `file://` as secure enough for the Web Crypto APIs this
app uses, so this works directly, no server needed.

**Option B — GitHub Pages (recommended for sharing a live link).**
1. Push this folder to a GitHub repository.
2. Repo Settings → Pages → Deploy from branch → pick `main` (or
   whichever branch) and the root folder.
3. Your site will be live at `https://<username>.github.io/<repo>/`.

**Option C — any static file server**, e.g.:
```bash
python3 -m http.server 8000
```
then open `http://localhost:8000`.

## How it works

- **Issue tab** — fill in recipient/course/institution/date. The app
  hashes the certificate's fields with SHA-256, appends a new block to
  the ledger (linking to the previous block's hash), and shows a QR
  code encoding the certificate ID + hash.
- **Verify tab** — look up a certificate by ID. The app re-hashes the
  stored data and compares it against the saved hash and the ledger's
  copy of it, then walks the *entire* ledger to confirm no block's
  hash or `prev_hash` pointer has been altered.
- **Scan QR tab** — uses your camera (via the `jsQR` library) to read
  a certificate's QR code and verify it the same way.
- **Registry tab** — lists every certificate issued in this browser,
  with a Revoke action.
- **Ledger tab** — shows every block in the hash chain and a
  "Check Chain Integrity" button that re-validates the whole chain.

Any of these make a certificate come back as **Tampered**:
- Someone edits a stored certificate's fields directly (its hash no
  longer matches what was recorded).
- Someone edits or reorders a ledger block (the chain's hash pointers
  break).
- A scanned QR code's embedded hash doesn't match the certificate's
  current stored hash.

## Data storage & limitations — please read

- **Data lives only in the browser you used to issue it.**
  `localStorage` is per-browser, per-device, per-origin. A certificate
  issued on your laptop will not show up if you open the same page on
  your phone, in a different browser, or in an incognito window. This
  is a genuine limitation of a backend-free design, not a bug — it's
  the trade-off for "no server to run."
- Clearing your browser's site data / cache for this page will erase
  every certificate and the whole ledger.
- There is no authentication — anyone with the page open can issue or
  revoke certificates in their own browser's copy of the data.
- The ledger is tamper-*evident*, not tamper-*proof*: it detects
  edits made through normal use of the page, but someone who opens
  their browser's dev tools and directly rewrites `localStorage`
  consistently (recomputing every hash correctly) could still forge a
  self-consistent chain. A production system would anchor the ledger
  to a server, database, or public blockchain that a client cannot
  rewrite.
- `jsQR` and a small QR-generation library are loaded from a CDN
  (`cdnjs.cloudflare.com`) in `index.html`, so an internet connection
  is required for QR generation and scanning to work; the rest of the
  app works fully offline once loaded.

## If you need a real multi-user backend

If certificates need to be verifiable by *other people*, from *their
own* devices — the realistic use case for something called
"certificate verification" — this static version isn't enough on its
own, since its data never leaves the issuer's browser. That needs a
real shared datastore (a small server + database). Ask if you'd like
that version — the original Flask + SQLite backend (with the same
hashing/ledger/fraud logic, just server-side) is a natural fit and was
already built in this project's earlier iteration.

## License

Use, modify, and adapt freely for your own projects.
