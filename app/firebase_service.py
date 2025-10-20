# app/firebase_service.py
import firebase_admin
from firebase_admin import credentials, messaging
import os

# --- IMPORTANT ---
# 1. Go to your Firebase project settings -> Service accounts.
# 2. Click "Generate new private key" and download the JSON file.
# 3. Save this file in the root of your project (the same level as run.py).
# 4. Rename the file to "firebase-service-account.json".
# 5. Make sure this file is listed in your .gitignore to keep it private!

try:
    cred_path = os.path.join(os.path.dirname(__file__), '..', 'firebase-service-account.json')
    cred = credentials.Certificate(cred_path)
    firebase_admin.initialize_app(cred)
    print("Firebase App initialized successfully.")
except Exception as e:
    print(f"Error initializing Firebase App: {e}")
    # The app will still run, but push notifications will fail.

def send_push_notification(token, title, body, data=None):
    """
    Sends a single push notification to a specific device.
    """
    if not firebase_admin._apps:
        print("Firebase App not initialized. Cannot send push notification.")
        return

    message = messaging.Message(
        notification=messaging.Notification(
            title=title,
            body=body,
        ),
        token=token,
        data=data or {} # Optional data payload
    )

    try:
        response = messaging.send(message)
        print('Successfully sent push notification:', response)
    except Exception as e:
        print('Error sending push notification:', e)