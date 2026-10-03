"""Generate a Gmail read-only refresh token locally without storing credentials."""

from __future__ import annotations

from getpass import getpass
from http.server import BaseHTTPRequestHandler, HTTPServer
import base64
import hashlib
import json
import secrets
from urllib.parse import parse_qs, urlencode, urlparse
from urllib.request import Request, urlopen
import webbrowser


REDIRECT_URI = "http://127.0.0.1:8765/"
AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
SCOPE = "https://www.googleapis.com/auth/gmail.readonly"


class _CallbackHandler(BaseHTTPRequestHandler):
    state = ""
    code = None
    error = None

    def do_GET(self):
        query = parse_qs(urlparse(self.path).query)
        if not secrets.compare_digest(query.get("state", [""])[0], self.state):
            type(self).error = "state_mismatch"
            status, message = 400, "Authorization state did not match. You can close this tab."
        elif query.get("error"):
            type(self).error = query["error"][0][:80]
            status, message = 400, "Gmail authorization was not completed. You can close this tab."
        elif query.get("code"):
            type(self).code = query["code"][0]
            status, message = 200, "Gmail authorization received. You can close this tab and return to the terminal."
        else:
            type(self).error = "authorization_code_missing"
            status, message = 400, "Authorization code was missing. You can close this tab."

        body = message.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        return


def main():
    client_id = input("Google OAuth client ID: ").strip()
    client_secret = getpass("Google OAuth client secret: ").strip()
    if not client_id or not client_secret:
        raise SystemExit("Client ID and secret are required.")

    state = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).decode("ascii").rstrip("=")
    _CallbackHandler.state = state
    _CallbackHandler.code = None
    _CallbackHandler.error = None
    server = HTTPServer(("127.0.0.1", 8765), _CallbackHandler)
    server.timeout = 300

    authorization_params = {
        'client_id': client_id,
        'redirect_uri': REDIRECT_URI,
        'response_type': 'code',
        'scope': SCOPE,
        'access_type': 'offline',
        'prompt': 'consent',
        'include_granted_scopes': 'true',
        'state': state,
        'code_challenge': challenge,
        'code_challenge_method': 'S256',
    }
    authorization_url = f"{AUTH_URL}?{urlencode(authorization_params)}"

    print("\nOpening Google consent. Grant only Gmail read-only access to the account you want monitored.")
    if not webbrowser.open(authorization_url):
        print("Open this URL in your browser:\n" + authorization_url)
    server.handle_request()
    server.server_close()
    if _CallbackHandler.error or not _CallbackHandler.code:
        raise SystemExit(f"Authorization did not complete: {_CallbackHandler.error or 'timed_out'}")

    body = urlencode({
        "client_id": client_id,
        "client_secret": client_secret,
        "code": _CallbackHandler.code,
        "code_verifier": verifier,
        "grant_type": "authorization_code",
        "redirect_uri": REDIRECT_URI,
    }).encode("ascii")
    request = Request(TOKEN_URL, data=body, headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urlopen(request, timeout=20) as response:
            token = json.load(response)
    except Exception as error:
        raise SystemExit(f"Google token exchange failed: {type(error).__name__}") from None

    refresh_token = token.get("refresh_token")
    if not refresh_token:
        raise SystemExit("Google did not return a refresh token. Revoke this app's access and run setup again.")

    print("\nCopy these values to the backend host's private environment settings:")
    print(f"GMAIL_CLIENT_ID={client_id}")
    print("GMAIL_CLIENT_SECRET=<the client secret from Google Cloud>")
    print(f"GMAIL_REFRESH_TOKEN={refresh_token}")
    print("GMAIL_MONITOR_ENABLED=true")
    print("\nThis token was not written to a file. Do not commit it or paste it into chat.")


if __name__ == "__main__":
    main()
