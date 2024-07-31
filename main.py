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
class EmailMessengerApp:
    def init(self):
        self.user_manager = UserManager()
        self.email_manager = EmailManager(self.user_manager)  # Initialize EmailManager
        self.current_user = None
        self.is_admin = False

    def run(self):
        print("Welcome to Email Messenger")

        while True:
            username = input("Username: ")
            password = input("Password: ")

            if username == "admin" and self.user_manager.is_valid_admin(
                username, password
            ):
                self.current_user = username
                self.is_admin = True
                print(f"Welcome Admin!")
                break
            else:
                authenticated, is_admin = self.user_manager.authenticate_user(
                    username, password
                )
                if authenticated:
                    self.current_user = username
                    self.is_admin = is_admin
                    print(f"Welcome {username}!")
                    break
                else:
                    print("Invalid username or password. Please try again.")

        while True:
            self.show_menu()

            choice = input("Choose an option: ")

            if choice == "1":
                self.send_email()
            elif choice == "2":
                self.view_emails()
            elif choice == "3":
                self.change_password()
            elif choice == "4" and self.is_admin:
                self.add_new_user()
            elif choice == "5":
                print("Goodbye!")
                break
            else:
                print("Invalid option. Please try again.") 
                 
    def show_menu(self):
        print("\nMenu:")
        print("1. Send email")
        print("2. See my emails")
        print("3. Change password")
        if self.is_admin:  # Only show this option if the user is an admin
            print("4. Add new user")
        print("5. Exit")

    def send_email(self):
        receiver = input("Enter receiver username: ")
        subject = input("Enter subject: ")
        content = input("Enter message content: ")
        cc_input = input("Enter CC usernames (comma separated, optional): ")
        cc = (
            [username.strip() for username in cc_input.split(",")] if cc_input else None
        )
        reply_to_id = input(
            "Replying to any email? (Enter email ID and sender username, separated by a comma, or leave blank): "
        ).strip()

        reply_to = None
        if reply_to_id:
            try:
                reply_to_id, reply_to_sender = [
                    item.strip() for item in reply_to_id.split(",", 1)
                ]
                reply_to_id = int(reply_to_id)
                reply_to_email = self.email_manager.get_email_by_id(
                    reply_to_id, reply_to_sender
                )
                if reply_to_email:
                    reply_to = reply_to_email.email_id
                else:
                    print(
                        f"No email found with ID: {reply_to_id} from sender: {reply_to_sender}"
                    )
                    return
            except ValueError:
                print("Invalid ID format. Please enter a numeric ID.")
                return

        success, message = self.email_manager.send_email(
            self.current_user, receiver, subject, content, cc, reply_to
        )
        print(message)

    def view_emails(self):
        emails = self.email_manager.get_user_emails(self.current_user)
        for email in emails:
            reply_info = (
                f"(Reply to ID: {email.reply_to})" if email.reply_to is not None else ""
            )
            print(
                f"ID: {email.email_id}, From: {email.sender}, To: {email.receiver}, Subject: {email.subject}, CC: {email.cc}, Time: {email.timestamp} {reply_info}"
            )
            print(f"Content: {email.content}\n")

    def change_password(self):
        old_password = input("Enter current password: ")
        new_password = input("Enter new password: ")
        confirm_password = input("Confirm new password: ")
        if new_password == confirm_password:
            success, message = self.user_manager.change_password(
                self.current_user, old_password, new_password
            )
            print(message)
        else:
            print("Passwords do not match.")

    def add_new_user(self):
        if not self.is_admin:
            print("Only admin can add new users.")
            return

        new_username = input("Enter new username: ")
        new_password = input("Enter new password: ")

        success, message = self.user_manager.add_user(new_username, new_password)
        print(message)


if name == "main":
    app = EmailMessengerApp()
    app.run()  
            
