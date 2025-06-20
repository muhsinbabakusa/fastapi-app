from fastapi.testclient import TestClient
from main1 import app

client = TestClient(app)

def test_register_user():
    response = client.post("/create_users", json={
        "firstName": "Test",
        "lastName": "User",
        "email": "test@example.com",
        "username": "testuser",
        "password": "testpassword"
    })

    assert response.status_code in [200, 400]

    if response.status_code == 200:
        data = response.json()
        assert data["message"].startswith("Test")
        assert data["data"]["username"] == "testuser"

def test_login_valid():
    response = client.post("/login", data={
        "username": "testuser",
        "password": "testpassword"
    })
    assert response.status_code == 200
    assert "access_token" in response.json()
    assert "refresh_token" in response.json()

def test_login_invalid():
    response = client.post("/login", data={
        "username": "wronguser",
        "password": "wrongpassword"
    })

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials"

def test_profile_access_with_token():
    # First, login to get a valid token
    login_response = client.post("/login", data={
        "username": "testuser",
        "password": "testpassword"
    })

    assert login_response.status_code == 200
    token = login_response.json()["access_token"]

    # Access profile with token
    response = client.get("/profile", headers={
        "Authorization": f"Bearer {token}"
    })

    assert response.status_code == 200
    assert response.json()["username"] == "testuser"

 