# OFFTune Business Desk

A local first prototype for an education business sales and finance workspace. It stores its data in a SQLite file on this computer.

## Start it on macOS

1. Open Terminal.
2. Run `cd "/Users/riksahin/Documents/Codex/2026-10-29/realtime-voice-chat"`
3. Run `python3 app.py`.
4. In your browser, open `http://127.0.0.1:8000`.
5. Create the founder account on the first screen. Use a unique password with at least 12 characters.

Keep the Terminal window open while using the app. Press Control-C in that window when you want to stop it. The database is saved in `data/offtune.sqlite3` and remains on this computer between runs.

## Current scope

- Founder dashboard, configurable catalog prices, orders, admission fees, monthly EMI schedules, receipts/refunds, expenses, incentives, invoice register, team accounts, conversion targets, batch/course reports, and monthly cash reports.
- A sale stores its commission rate. Each receipt (including an admission fee collected at sale) creates an incentive record using that saved rate.
- Owner Settings includes Gmail, Outlook/Microsoft 365, and custom SMTP sender setup. The connection check validates secure SMTP login only; it does not send an email. SMTP credentials are kept in a separate owner-only file next to the database and are not included in workspace exports. Keep server backups private.
- Employees can see only their incentive totals and history. Managers see their direct team's conversions, targets, incentives, received cash, and due balance. The founder can see workspace totals.
- Product types include courses, sample packs, and digital products. Course and batch labels from the supplied workbook are included as setup drafts. The two prices supplied as examples are marked as examples. Additional OFFTune website offerings are preloaded as inactive review drafts; public prices can change and must be confirmed before real sales.
- The shared workspace voice agent uses the owner-configured OpenRouter key and model. Signed-in owners, managers, and employees can use it; supported action proposals are limited by designation, and the server checks designation access again when an action is confirmed. Sales, receipts, invoice drafts, targets, follow-ups, reminder settings, invoice templates, business settings, expenses, products, batches, team messages, and incentive payouts have guarded proposal flows where permitted. Sending an invoice from the voice agent opens the full preview inside the conversation and requires a second spoken or on-screen confirmation before queueing the email. The agent cannot delete records, change credentials, or create Razorpay payment links. Browser speech recognition and built-in spoken replies support Bengali, Hindi, and English where the browser supplies those voices; OpenRouter speech output is optional. Model and voice catalogs refresh from OpenRouter and may change. Chat requires explicit consent; limited workspace references are sent to OpenRouter, without automatically attaching student phone numbers or email addresses. Messages are not stored by OFFTune.
- For a local preview, the OpenRouter key is stored in `data/.ai-provider.json` with owner-only file permissions. Hosted servers can instead inject `OPENROUTER_API_KEY` and optionally `OPENROUTER_MODEL` as server secrets. Keys are never returned by the API or included in workspace exports. Do not commit the `data/` directory or share a key.
- OpenRouter model usage is billed to the OpenRouter account associated with the key. The settings page links to OpenRouter's credit page but does not accept or process credit purchases. Free endpoints have provider-side limits and may be temporarily unavailable.
- `OFFTUNE_DISABLE_WORKERS=1` starts a preview without the in-process reminder delivery worker. Use this for isolated UI/API checks so test startup cannot send scheduled email.

## Optional Gemini Live egress relay

Some local or hosted runtimes block direct outbound requests to Google. An optional Cloudflare Worker relay is provided in `cloudflare/`. The Python app signs a short-lived, single-use ticket after checking the signed-in user and role; the browser exchanges that ticket with the Worker, which creates a single-use Gemini Live session. The Gemini API key stays in a Cloudflare secret and is never sent to the browser or stored by the app when relay mode is used.

For local development, install Wrangler in `cloudflare/`, set Worker secrets `GEMINI_API_KEY` and `GEMINI_LIVE_BRIDGE_SECRET`, then deploy the Worker. Generate one random bridge secret of at least 32 characters and use that same value only in the Worker secret store and Python server environment. Set `GEMINI_LIVE_WORKER_URL` to the deployed Worker URL ending in `/v1/live-token`, and set the same `GEMINI_LIVE_BRIDGE_SECRET` in the app server environment. Set `APP_ORIGINS` to the exact app origins; the checked-in localhost values are for local development only. Never commit either secret. When both app-side relay variables are present, live-session token issuance uses the Worker instead of requiring direct Google access from the Python server. The existing local direct-Gemini path remains available when relay mode is not configured.

## Before using for business-critical records

This is still a local prototype; it has not had an independent security or accounting review. Keep it on this computer and use sample records first. Back up the SQLite database before entering real records. Workbook student rows are not imported; scheduled email reminders, scheduled/automatic payment collection, remote access, ongoing backups, and account recovery still need dedicated setup. The built-in server is only bound to this computer and should not be exposed directly to the public internet.

## GitHub and hosted deployment

The source is uploaded to the public GitHub repository `offtunestudio-prog/OFFTune-business-Desk`; this is not a live deployment. The local database, provider credentials, and customer records are excluded. A hosted release needs a separate deployment adaptation: replace local SQLite and cookie/session storage with Supabase Postgres/Auth plus row-level security, move the request handlers from Python `http.server` to FastAPI, and replace the in-process reminder worker with a scheduled/queued delivery service. Cloudflare supports Python Workers with FastAPI, but the current socket server, SQLite database, and thread-based worker cannot be deployed as-is. The assistant currently uses a server-side OpenRouter request; hosted deployment must store that key in a server secret, never a browser setting. Free-plan limits and inactivity pausing should be reviewed before relying on it for business records.

See [DEPLOYMENT.md](DEPLOYMENT.md) for the hosting path, account independence, and release checks. Cloudflare is not connected to this repository for automatic deploys yet. After the hosted app is ready and connected, pushes to its production branch can trigger deployment. ChatGPT is only a way to edit the code; the running app and deployment continue under the owner's GitHub, Cloudflare, and Supabase accounts if a ChatGPT subscription or account changes.
