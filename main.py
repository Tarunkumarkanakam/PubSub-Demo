from fastapi import FastAPI, HTTPException, Request
from starlette.middleware.sessions import SessionMiddleware
from starlette.config import Config
from authlib.integrations.starlette_client import OAuth, OAuthError

import json
import base64
import logging
import os

from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.oauth2.credentials import Credentials

logging.basicConfig(level=logging.INFO)
SCOPES = 'email openid profile https://www.googleapis.com/auth/gmail.readonly https://mail.google.com'


app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key="add any string...")

oauth = OAuth()
oauth.register(
    name='google',
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_id="##",
    client_secret="##",
    client_kwargs={
        'scope': SCOPES,
        'redirect_url': 'http://localhost:8000/auth/google'
    }
)


@app.get("/login/google")
async def login_via_google(request: Request):
    redirect_uri = request.url_for('auth_via_google')
    return await oauth.google.authorize_redirect(request, redirect_uri)


@app.get("/auth/google")
async def auth_via_google(request: Request):
    token = await oauth.google.authorize_access_token(request)
    user = token['userinfo']
    with open('gmail_token.json', 'w') as f:
        json.dump(token, f)
    return dict(user)


@app.post("/webhook/gmail")
def gmail_webhook(request: Request):
    # logging.INFO("Email Recieved")
    print("recieved")
    return "ok"


@app.post("/webhook")
async def webhook_handler(request: Request):
    try:
        # Parse the incoming Pub/Sub notification
        body = await request.json()

        # Decode the message
        message_data = base64.b64decode(
            body["message"]["data"]).decode("utf-8")
        message = json.loads(message_data)  # JSON decode the message data

        # Extract Gmail details (historyId, etc.)
        history_id = message.get("historyId")
        # The Gmail address tied to this notification
        email = message.get("emailAddress")

        # Log the notification details (for debugging)
        print(f"Received notification: historyId={history_id}, email={email}")

        # TODO: Use the Gmail API to fetch new emails based on the `historyId`
        # Example:
        # fetch_new_emails_from_gmail(history_id)

        return {"status": "success", "message": "Webhook received"}

    except Exception as e:
        print(f"Error handling webhook: {e}")
        raise HTTPException(status_code=400, detail="Invalid Pub/Sub message")
