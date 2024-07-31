import os
import json
import hashlib
import datetime

USER_FILE = "users.json"
EMAIL_FILE = "emails.json"

# Check if 'users.json' exists; if not, create it with the admin user.
if not os.path.exists(USER_FILE):
    admin_data = {
        "username": "admin",
        "password": hashlib.sha256("admin".encode()).hexdigest(),
        "is_admin": True,
    }

    with open(USER_FILE, "w") as f:
        json.dump([admin_data], f)

    print("Admin user initialized successfully.")


class UserManager:
    def __init__(self):
        self.users = self.load_users()

    def load_users(self):
        if not os.path.exists(USER_FILE):
            return {}
        with open(USER_FILE, "r") as file:
            try:
                user_data = json.load(file)
                return user_data if isinstance(user_data, dict) else {}
            except json.JSONDecodeError:
                print("Error: Failed to decode users.json.")
                return {}

    def save_users(self):
        with open(USER_FILE, "w") as file:
            json.dump(self.users, file)

    def add_user(self, username, password, is_admin=False):
        if username in self.users:
            return False, "Username already exists."

        # Ensure only one admin exists
        if is_admin:
            for user in self.users.values():
                if user["is_admin"]:
                    return False, "An admin already exists. Only one admin is allowed."

        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        self.users[username] = {"password": hashed_password, "is_admin": is_admin}
        self.save_users()
        return True, "User added successfully"

    def authenticate_user(self, username, password):
        if username not in self.users:
            return False, False

        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        user = self.users[username]
        if user["password"] == hashed_password:
            return True, user["is_admin"]
        return False, False

    def is_valid_admin(self, username, password):
        if username == "admin":
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            return self.users.get("admin", {}).get("password") == hashed_password
        return False

    def user_exists(self, username):
        return username in self.users

    def change_password(self, username, old_password, new_password):
        if username not in self.users:
            return False, "User not found."

        hashed_old_password = hashlib.sha256(old_password.encode()).hexdigest()
        user = self.users[username]
        if user["password"] == hashed_old_password:
            hashed_new_password = hashlib.sha256(new_password.encode()).hexdigest()
            user["password"] = hashed_new_password
            self.save_users()
            return True, "Password updated successfully."
        return False, "Old password is incorrect."