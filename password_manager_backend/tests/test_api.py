import pytest
from fastapi.testclient import TestClient
from src.api.main import app, encryption_manager, hash_password, verify_password, get_user

client = TestClient(app)

# Test configuration helpers

def register_user(email="alice@example.com", password="ALongP@ssword!"):
    r = client.post("/auth/register", json={"email": email, "password": password})
    return r

def login_user(email="alice@example.com", password="ALongP@ssword!"):
    r = client.post("/auth/token", data={"username": email, "password": password})
    return r

def auth_header(token):
    return {"Authorization": f"Bearer {token}"}

# ---------- EncryptionManager unit tests ----------

def test_encryption_and_decryption_roundtrip():
    sample = "myS3cret!"
    encrypted = encryption_manager.encrypt(sample)
    assert isinstance(encrypted, str)
    assert encrypted != sample
    decrypted = encryption_manager.decrypt(encrypted)
    assert decrypted == sample

def test_encryption_manager_wrong_key_raises():
    bad_manager = type(encryption_manager)(Fernet.generate_key())
    token = encryption_manager.encrypt("topSecret")
    with pytest.raises(ValueError):
        bad_manager.decrypt(token)

# ---------- Password hashing ----------

def test_password_hash_and_verify():
    pw = "SomePa$$w0rd"
    hashed = hash_password(pw)
    assert hashed != pw
    assert verify_password(pw, hashed)
    assert not verify_password("wrong", hashed)

# ---------- Registration and Login ----------

def test_user_registration_and_duplicate():
    r = register_user("bob@mail.com", "UltraS3cretPW!")
    assert r.status_code == 201
    body = r.json()
    assert "id" in body and body["email"] == "bob@mail.com"
    # Duplicate registration
    r2 = register_user("bob@mail.com", "AnotherPW1234!")
    assert r2.status_code == 400
    assert r2.json()["detail"] == "Email already registered."

def test_user_login_success_and_fail():
    email = "cathy@testmail.com"
    password = "StrongPass987!"
    register_user(email, password)
    r = login_user(email, password)
    assert r.status_code == 200
    token = r.json()["access_token"]
    assert isinstance(token, str) and r.json()["token_type"] == "bearer"
    # Wrong password
    r2 = login_user(email, "failpass")
    assert r2.status_code == 401
    # Nonexistent user
    r3 = login_user("nouser@none.com", "irrelevantPW")
    assert r3.status_code == 401

def test_get_me_requires_auth():
    register_user("me@host.org", "SafePW$$$888")
    token = login_user("me@host.org", "SafePW$$$888").json()["access_token"]
    r = client.get("/users/me", headers=auth_header(token))
    data = r.json()
    assert data["email"] == "me@host.org"
    # no token
    r2 = client.get("/users/me")
    assert r2.status_code == 401

# ---------- Password CRUD ----------

@pytest.fixture
def user_token():
    email = "apiuser@pwman.io"
    pw = "Password123@_"
    register_user(email, pw)
    r = login_user(email, pw)
    assert r.status_code == 200
    return r.json()["access_token"]

def create_password_entry(token, site="github", username="gituser", password="g1t_p@ss", notes="dev notes"):
    resp = client.post(
        "/passwords/",
        headers=auth_header(token),
        json={"site": site, "username": username, "password": password, "notes": notes}
    )
    return resp

def test_create_password_entry_ok(user_token):
    resp = create_password_entry(user_token, site="gmail", username="mailme", password="mailPW!zx", notes="personal mail")
    assert resp.status_code == 201
    item = resp.json()
    assert item["site"] == "gmail" and item["username"] == "mailme"
    assert item["password"] == "mailPW!zx"  # returned only at creation
    assert item["notes"] == "personal mail"
    assert "created_at" in item and "updated_at" in item

def test_create_and_get_password_entry(user_token):
    resp = create_password_entry(user_token, site="fb", username="bob", password="pass_fb", notes="fblogin")
    assert resp.status_code == 201
    item = resp.json()
    pid = item["id"]
    # Retrieve
    get_resp = client.get(f"/passwords/{pid}", headers=auth_header(user_token))
    assert get_resp.status_code == 200
    got = get_resp.json()
    assert got["site"] == "fb" and got["username"] == "bob"
    assert got["password"] == "pass_fb"
    assert got["notes"] == "fblogin"

def test_list_passwords_search(user_token):
    create_password_entry(user_token, site="Twitter", username="tw_user", password="abc", notes="")
    create_password_entry(user_token, site="LinkedIn", username="in_user", password="xyz", notes="")
    resp = client.get("/passwords/?search=twitter", headers=auth_header(user_token))
    assert resp.status_code == 200
    results = resp.json()
    assert len(results) == 1 and results[0]["site"].lower() == "twitter"
    # No match
    resp2 = client.get("/passwords/?search=nope", headers=auth_header(user_token))
    assert resp2.status_code == 200 and resp2.json() == []

def test_update_password_entry(user_token):
    create = create_password_entry(user_token, site="Yahoo", username="y_mail", password="oldpw", notes="legacy")
    pid = create.json()["id"]
    payload = {"site": "Yahoo", "username": "y_mail", "password": "newpw", "notes": "updated"}
    r = client.put(f"/passwords/{pid}", headers=auth_header(user_token), json=payload)
    assert r.status_code == 200
    got = r.json()
    assert got["password"] == "newpw"
    assert got["notes"] == "updated"

def test_delete_password_entry(user_token):
    create = create_password_entry(user_token, site="Shopify", username="store", password="delme", notes="")
    pid = create.json()["id"]
    r = client.delete(f"/passwords/{pid}", headers=auth_header(user_token))
    assert r.status_code == 204
    # Should return 404 now
    getagain = client.get(f"/passwords/{pid}", headers=auth_header(user_token))
    assert getagain.status_code == 404

def test_copy_password_endpoint(user_token):
    create = create_password_entry(user_token, site="Apple", username="iosman", password="iphonesecret", notes="")
    pid = create.json()["id"]
    r = client.post(f"/passwords/{pid}/copy", headers=auth_header(user_token))
    assert r.status_code == 200
    assert r.json()["password"] == "iphonesecret"

# --------- Error and edge case tests ----------

def test_create_password_requires_auth():
    # No token
    r = client.post("/passwords/", json={"site": "t", "username": "u", "password": "pw", "notes": ""})
    assert r.status_code == 401

def test_get_password_not_found(user_token):
    fakeid = "dXNlcmlkFAKEID"
    r = client.get(f"/passwords/{fakeid}", headers=auth_header(user_token))
    assert r.status_code == 404
    assert r.json()["detail"] == "Password entry not found."

def test_update_password_404(user_token):
    id = "madeup123"
    payload = {"site": "NOWHERE", "username": "noone", "password": "pass", "notes": ""}
    r = client.put(f"/passwords/{id}", headers=auth_header(user_token), json=payload)
    assert r.status_code == 404
    assert r.json()["detail"] == "Password entry not found."

def test_delete_password_404(user_token):
    id = "notanid"
    r = client.delete(f"/passwords/{id}", headers=auth_header(user_token))
    assert r.status_code == 404
    assert r.json()["detail"] == "Password entry not found."

def test_core_utils_fake_user_db_is_isolated_between_tests():
    # Register, login, check isolation via different user
    email1, pw1 = "test1@test.com", "pw1testPW##"
    email2, pw2 = "test2@test.com", "pw2testPW##"
    register_user(email1, pw1)
    register_user(email2, pw2)
    assert get_user(email1).email == email1
    assert get_user(email2).email == email2
    assert get_user("ghost@none.com") is None

def test_health_check_works():
    r = client.get("/")
    assert r.status_code == 200
    assert r.json() == {"status": "Healthy"}

# Convenience: required for encryption negative test
from cryptography.fernet import Fernet
