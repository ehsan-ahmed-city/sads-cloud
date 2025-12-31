import os
from auth.cognito import sign_up, sign_in

email = os.environ.get("SADS_TEST_EMAIL")
password = os.environ.get("SADS_TEST_PASSWORD")

if not email or not password:
    raise RuntimeError("Set SADS_TEST_EMAIL and SADS_TEST_PASSWORD")

print("Signing up...")
try:
    sign_up(email, password)
    print("Sign-up OK.")
except Exception as e:
    print("Sign-up error (maybe already exists):", e)

print("Signing in...")
tokens = sign_in(email, password)
print("Access token:", tokens["access_token"])
print("ID token (first 40):", tokens["id_token"][:40])
