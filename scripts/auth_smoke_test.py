from auth.cognito import sign_up, sign_in

email = "ehsan.test1@example.com"
password = "Password123!"

print("Signing up...")
try:
    sign_up(email, password)
    print("Sign-up Ok.")
except Exception as e:
    print("Sign-up error (maybe already exists): ", e)

print("Signing in...")
tokens = sign_in(email, password)
print("Access token (first 40):", tokens["access_token"][:40])
print("ID token (first 40):", tokens["id_token"][:40])
