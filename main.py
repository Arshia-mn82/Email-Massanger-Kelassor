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


class Email:
    def __init__(
        self,
        sender,
        receiver,
        subject,
        content,
        email_id,
        cc=None,
        reply_to=None,
        timestamp=None,
    ):
        self.sender = sender
        self.receiver = receiver
        self.subject = subject
        self.content = content
        self.email_id = email_id  # Numeric ID for each email
        self.cc = cc if cc else []
        self.reply_to = reply_to
        self.timestamp = timestamp if timestamp else datetime.datetime.now().isoformat()

    def __repr__(self):
        return f"Email(ID: {self.email_id}, From: {self.sender}, To: {self.receiver}, Subject: {self.subject})"


class EmailManager:
    def __init__(self, user_manager):
        self.user_manager = user_manager
        self.emails = self.load_emails()
        self.email_counters = self.initialize_email_counters()

    def initialize_email_counters(self):
        # Initialize email counters for each user
        counters = {}
        for email in self.emails:
            if email.sender not in counters:
                counters[email.sender] = 0
            if email.receiver not in counters:
                counters[email.receiver] = 0

            # Update counter for sender and receiver
            counters[email.sender] = max(counters[email.sender], email.email_id + 1)
            counters[email.receiver] = max(counters[email.receiver], email.email_id + 1)
        return counters

    def load_emails(self):
        if not os.path.exists(EMAIL_FILE):
            return []
        with open(EMAIL_FILE, "r") as file:
            email_data = json.load(file)
            return [Email(**email) for email in email_data]

    def save_emails(self):
        with open(EMAIL_FILE, "w") as file:
            email_data = [email.__dict__ for email in self.emails]
            json.dump(email_data, file)

    def get_next_email_id(self, username):
        if username not in self.email_counters:
            self.email_counters[username] = 0
        next_id = self.email_counters[username]
        self.email_counters[username] += 1
        return next_id

    def send_email(self, sender, receiver, subject, content, cc=None, reply_to=None):
        # Check if the receiver exists
        if not self.user_manager.user_exists(receiver):
            return False, f"Receiver '{receiver}' does not exist."

        # Check if all CC users exist
        if cc:
            for user in cc:
                if not self.user_manager.user_exists(user):
                    return False, f"CC user '{user}' does not exist."

        # Assign a new email ID
        email_id = self.get_next_email_id(sender)
        new_email = Email(sender, receiver, subject, content, email_id, cc, reply_to)
        self.emails.append(new_email)
        self.save_emails()
        return True, "Email sent successfully"

    def get_user_emails(self, username):
        user_emails = [
            email
            for email in self.emails
            if email.sender == username
            or email.receiver == username
            or username in email.cc
        ]
        user_emails.sort(key=lambda x: x.timestamp, reverse=True)
        return user_emails

    def get_email_by_id(self, email_id, sender_username):
        for email in self.emails:
            if email.email_id == email_id and email.sender == sender_username:
                return email
        return None
