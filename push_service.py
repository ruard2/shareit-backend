# push_service.py
import os, requests
from google.oauth2 import service_account
from google.auth.transport.requests import Request

SCOPES = ["https://www.googleapis.com/auth/firebase.messaging"]
SA_PATH = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")  # you already set this
PROJECT_ID = os.environ.get("FIREBASE_PROJECT_ID", "free-your-stuff-fd9a3")  # <- adjust if different

def _access_token() -> str:
    creds = service_account.Credentials.from_service_account_file(SA_PATH, scopes=SCOPES)
    creds.refresh(Request())
    return creds.token

def send_fcm_to_token(token: str, title: str, body: str, data: dict | None = None) -> tuple[bool, str]:
    url = f"https://fcm.googleapis.com/v1/projects/{PROJECT_ID}/messages:send"
    msg = {
        "message": {
            "token": token,
            "notification": {"title": title, "body": body},
            "data": {k: str(v) for k, v in (data or {}).items()},
            "android": {"priority": "high"},
        }
    }
    headers = {
        "Authorization": f"Bearer {_access_token()}",
        "Content-Type": "application/json; UTF-8",
    }
    r = requests.post(url, headers=headers, json=msg, timeout=10)
    ok = 200 <= r.status_code < 300
    return ok, r.text if not ok else ""
