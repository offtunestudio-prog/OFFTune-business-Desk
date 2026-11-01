# Hosting and automatic updates

## What is ready today

This project is a local Python application. `app.py` starts a `ThreadingHTTPServer`, stores business data in a local SQLite file, and reads a few credentials from local files. The listen address can now be configured with `OFFTUNE_HOST`, but that alone does not make the app safe to expose publicly. The `cloudflare/` directory contains only the Gemini Live token relay; it is not the business application backend. The current app therefore cannot be made public by deploying the existing Cloudflare Worker alone.

The Git ignore rules exclude the local database, SQLite journal files, local settings, backup exports, and scratch work. Keep these exclusions in place when creating the GitHub repository. Never put API keys, SMTP credentials, student records, or database backups in GitHub.

The connected Supabase project now has the first versioned migration applied: workspace, profile, and workspace-member tables; owner bootstrap; and row-level policies for self, owner, and direct-manager access. All three tables have RLS enabled and currently contain zero rows. Security advisors report no findings. Performance advisors report only unused indexes because these new tables are empty; foreign-key index warnings are cleared. No student, sale, payment, invoice, or expense records have been moved.

## Production direction

Keep the existing web interface, then move the data and server responsibilities to hosted services:

1. Use Supabase Auth for sign-in and Postgres for workspace data. Convert the SQLite schema and business actions in reviewed, versioned migrations. Add workspace ownership and membership checks with Row Level Security to every exposed business table. Do not copy the current password hashes into Supabase Auth; users will need a secure account invitation or password reset during cutover.
2. Move the Python request handlers from `http.server` to FastAPI. Cloudflare Workers supports Python Workers and FastAPI, so the business logic can stay in Python, but the current socket server cannot be carried over as-is. Replace SQLite with Supabase Postgres calls, and replace the process-wide reminder thread with a scheduled or queued hosted job.
3. Serve the existing static web interface alongside the FastAPI Worker using Cloudflare Workers Static Assets. Keep privileged operations server-side, including invoice email delivery, payment-provider webhooks, AI keys, and reminder scheduling. Never put Supabase secret keys, Gemini keys, SMTP passwords, or Razorpay secrets in browser code or Git.
4. Connect the GitHub repository to Cloudflare Workers Builds after the production Worker builds and passes test-data checks. Pushes to the selected production branch can then deploy automatically. Preview branches should use test data and separate secrets.
5. Connect only the chosen subdomain after the public app URL and HTTPS are confirmed. Keep the Wix root domain and its other records unchanged.

## Account independence

After the GitHub repository and hosting accounts are connected, the deployed app does not depend on a ChatGPT subscription or on which ChatGPT account is used. The app keeps running under the owner's GitHub, Cloudflare, and Supabase accounts. Another ChatGPT account can help edit it only if that person/account has access to the same repository. Provider API usage (for example Gemini, OpenRouter, email, or Razorpay) remains tied to the credentials configured for the deployed app, not to ChatGPT.

## Current blockers before public deployment

- No Git repository or GitHub remote is configured in this folder yet.
- SQLite, local credential files, and the current Python HTTP server need a production architecture; the current code is not a Cloudflare Pages/Workers deployment.
- Supabase currently contains only the empty workspace/auth foundation; business tables, sign-in integration, and data migration are still required. Its URL, public key, and server-side secrets must be configured without committing them.
- The Cloudflare Gemini relay still has localhost origins in `wrangler.toml`; production origins must be exact HTTPS URLs before that relay is deployed.
- No production subdomain was provided, so no Wix DNS record should be changed yet.
- Reminder sending, account recovery, production backups, and payment webhooks need a hosted implementation and a test environment before real customer data is used.

## Deployment gates

Do not enable production auto-deploy until the Supabase migrations and access policies are reviewed, the app uses hosted persistence and authentication, secret handling is verified, the build succeeds, and invoice/payment/reminder flows pass against test data. Connect GitHub to the production host only after those gates pass; then every push/merge to the production branch can publish the accepted build.
