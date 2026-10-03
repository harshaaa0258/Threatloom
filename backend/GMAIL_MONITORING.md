# Gmail / Google Workspace monitoring

The optional mailbox monitor checks only new Inbox messages after it is first connected. It polls Gmail history every 30 seconds by default, does not mark messages as read, and never modifies or sends mail. Existing messages are not backfilled. Messages larger than 10 MB are skipped.

The monitor parses the message in memory and runs Threatloom's classifier and rules. It does not save the message body, sender, subject, URLs, or detailed analysis to the investigation database. The database stores a Gmail history cursor, a hashed account identifier, message IDs for de-duplication, and generic alert metadata (risk score and classification). Alert summaries do not include sender or subject.

The initial history cursor deliberately skips old mail. If Gmail reports that a stored cursor is no longer valid, the monitor resets to the current mailbox position and records `history_cursor_reset`; messages created during that gap may be missed. Keep the monitor database on persistent storage to preserve the cursor across restarts.

Third-party reputation lookups are disabled for monitored Gmail messages by default. SPF, DKIM, and DMARC checks still make DNS queries. Set `GMAIL_ENABLE_EXTERNAL_INTEL=true` only if you want extracted IPs, domains, and URLs checked by configured reputation providers and public feeds.

## Google Cloud setup

1. Create or select a Google Cloud project and enable the Gmail API.
2. Configure the OAuth consent screen. For a Workspace account within one organization, use the internal audience when available. For a personal Gmail account or external Workspace account, add the account as a test user while developing.
3. Create an OAuth client with application type **Desktop app**. Use the account you intend to monitor.
4. From the repository's `backend` directory, run `python gmail_oauth_setup.py`. The helper opens Google's consent page and requests only `https://www.googleapis.com/auth/gmail.readonly`. It asks for the client secret without echoing it, then prints the client ID and refresh token; it does not write credentials to disk.
5. Add those values to the backend host's private environment settings (Render for the current deployment):

   ```text
   GMAIL_CLIENT_ID=...
   GMAIL_CLIENT_SECRET=...
   GMAIL_REFRESH_TOKEN=...
   GMAIL_MONITOR_ENABLED=true
   ```

6. Redeploy the backend. The dashboard's Gmail monitoring panel should change from **not configured** to **monitoring new mail** after its first successful sync.

Optional settings:

```text
GMAIL_POLL_INTERVAL_SECONDS=30
GMAIL_ENABLE_EXTERNAL_INTEL=false
# Optional: place monitor cursors on a persistent mounted disk.
GMAIL_MONITOR_DB_PATH=/var/data/gmail_monitor.db
```

The poll interval is clamped to 15-300 seconds. If the backend host uses an ephemeral filesystem, point `GMAIL_MONITOR_DB_PATH` at a persistent mounted disk so the history cursor survives restarts. Keep all OAuth values in the backend's secret store; do not put them in the frontend, commit them, or paste them into chat. To stop monitoring, set `GMAIL_MONITOR_ENABLED=false` or remove the Gmail variables and redeploy. To revoke access, remove Threatloom from the Google Account's third-party access page.

## Google verification and testing limits

`gmail.readonly` is a restricted Gmail scope. Google may require OAuth verification before a public app can request it broadly, and restricted-scope data accessed through a server can require a security assessment. An external OAuth app left in Testing also has limited test users and its Gmail authorization can expire after seven days. Review Google's current [Gmail scope guidance](https://developers.google.com/workspace/gmail/api/auth/scopes) and [restricted-scope verification requirements](https://developers.google.com/identity/protocols/oauth2/production-readiness/restricted-scope-verification) before enabling this for other people's mailboxes.
