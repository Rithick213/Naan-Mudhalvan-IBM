import hashlib
import random

class User:
    def __init__(self, username, password):
        self.username = username
        self.password_hash = self.hash_password(password)
        self.mfa_enabled = False
        self.role = 'user'

    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()

    def enable_mfa(self):
        self.mfa_enabled = True

    def authenticate(self, password):
        return self.password_hash == self.hash_password(password)

    def grant_admin_privileges(self):
        self.role = 'admin'

class SocialNetwork:
    def __init__(self):
        self.users = {}

    def register_user(self, username, password):
        if username in self.users:
            print("Username already exists!")
            return

        user = User(username, password)
        self.users[username] = user
        print("User registered successfully.")

    def login(self, username, password):
        if username not in self.users:
            print("User does not exist!")
            return False

        user = self.users[username]
        if user.authenticate(password):
            print("Login successful.")
            return True
        else:
            print("Invalid credentials.")
            return False

    def enable_mfa(self, username):
        if username not in self.users:
            print("User does not exist!")
            return

        user = self.users[username]
        user.enable_mfa()
        print("Multi-factor authentication enabled.")

    def grant_admin_privileges(self, admin_username, target_username):
        if admin_username not in self.users or self.users[admin_username].role != 'admin':
            print("Unauthorized action!")
            return

        target_user = self.users.get(target_username)
        if not target_user:
            print("Target user does not exist!")
            return

        target_user.grant_admin_privileges()
        print(f"Admin privileges granted to {target_username}.")

# Example usage
if __name__ == "__main__":
    social_network = SocialNetwork()

    # Register users
    social_network.register_user("user1", "password1")
    social_network.register_user("admin1", "password1")

    # Login
    social_network.login("user1", "password1")
    social_network.login("user1", "wrong_password")

    # Enable MFA
    social_network.enable_mfa("user1")

    # Grant admin privileges
    social_network.grant_admin_privileges("admin1", "user1")
