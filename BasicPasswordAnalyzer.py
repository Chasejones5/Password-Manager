import re
from cryptography.fernet import Fernet
import bcrypt
import random
import string
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import tkinter as tk
from tkinter import messagebox, simpledialog, Menu
import os
from dotenv import load_dotenv
from datetime import datetime, timedelta
from pymongo import MongoClient

# Load environment variables from .env file
load_dotenv()

# MongoDB Setup and Connection
mongo_uri = os.getenv('MONGO_URI')
client = MongoClient(mongo_uri)
db = client['storepasswords']  # Replace with your database name
users_collection = db['passwords']  # Replace with your collection name

# Constants
LAST_CHANGE_FILE = 'last_password_change.txt'  # File to store last password change date
key = Fernet.generate_key()  # Generate a key for encryption

# Email Settings
SMTP_SERVER = os.getenv('SMTP_SERVER')
SMTP_PORT = int(os.getenv('SMTP_PORT'))
EMAIL_ADDRESS = os.getenv('EMAIL_ADDRESS')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')


# Function to check password strength
def check_password_strength(password):
    length_criteria = len(password) >= 8
    lowercase_criteria = re.search(r'[a-z]', password) is not None
    uppercase_criteria = re.search(r'[A-Z]', password) is not None
    digit_criteria = re.search(r'[0-9]', password) is not None
    special_char_criteria = re.search(r'[!@#$%^&*(),.?":{}|<>]', password) is not None
    score = sum([length_criteria, lowercase_criteria, uppercase_criteria, digit_criteria, special_char_criteria])

    if score == 5:
        return "Strong Password"
    elif score >= 3:
        return "Moderate Password"
    else:
        return "Weak Password"


# Function to hash a password
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    return hashed_password


# Function to encrypt a password
def encrypt_password(password, key):
    fernet = Fernet(key)
    encrypted_password = fernet.encrypt(password.encode())
    return encrypted_password


# Function to decrypt a password
def decrypt_password(encrypted_password, key):
    fernet = Fernet(key)
    decrypted_password = fernet.decrypt(encrypted_password).decode()
    return decrypted_password


# User management functions
def add_user():
    username = simpledialog.askstring("Add User", "Enter a username:")
    email = simpledialog.askstring("Add User", "Enter your email address:")

    if users_collection.find_one({"username": username}):
        messagebox.showerror("Error", "User already exists.")
    elif users_collection.find_one({"email": email}):
        messagebox.showerror("Error", "An account with this email already exists.")
    else:
        while True:
            password = simpledialog.askstring("Add User", "Enter a password:", show="*")
            if password:
                strength = check_password_strength(password)
                if strength == "Strong Password":
                    encrypted_pw = encrypt_password(password, key)
                    users_collection.insert_one({
                        "username": username,
                        "email": email,
                        "encrypted_password": encrypted_pw,
                        "date_added": datetime.now().isoformat()
                    })
                    messagebox.showinfo("Success", f"User {username} added.")
                    break
                else:
                    messagebox.showwarning("Weak Password", "Please choose a stronger password.")
            else:
                messagebox.showwarning("Input Error", "Password cannot be empty.")
                return





def delete_user():
    username = simpledialog.askstring("Delete User", "Enter the username to delete:")
    if users_collection.find_one({"username": username}):
        users_collection.delete_one({"username": username})
        messagebox.showinfo("Success", f"User {username} deleted.")
    else:
        messagebox.showerror("Error", "User does not exist.")


def view_password():
    username = simpledialog.askstring("View Password", "Enter the username:")
    user_record = users_collection.find_one({"username": username})
    if user_record:
        encrypted_password = user_record["encrypted_password"]
        decrypted_password = decrypt_password(encrypted_password, key)
        messagebox.showinfo("Password", f"{username}'s password is: {decrypted_password}")
    else:
        messagebox.showerror("Error", "User does not exist.")


# Password Recovery Function
def recover_password():
    # Ask for the username
    username = simpledialog.askstring("Recover Password", "Enter your username:")
    user_record = users_collection.find_one({"username": username})

    if user_record:
        # Ask for the email
        email = simpledialog.askstring("Recover Password", "Enter your email address:")

        # Verify the email matches the one in the database
        if user_record["email"] == email:
            # Generate recovery token
            recovery_token = generate_recovery_token()

            # Send the recovery token to the user's email
            send_recovery_email(email, recovery_token)

            # Prompt user to enter the token they received
            user_token = simpledialog.askstring("Password Recovery", "Enter the recovery token sent to your email:")

            if user_token == recovery_token:
                while True:
                    new_password = simpledialog.askstring("Password Recovery", "Enter your new password:")
                    if new_password:
                        strength = check_password_strength(new_password)
                        if strength == "Strong Password":
                            encrypted_pw = encrypt_password(new_password, key)
                            users_collection.update_one({"username": username},
                                                        {"$set": {"encrypted_password": encrypted_pw}})
                            update_password_change_date()
                            messagebox.showinfo("Password Recovery", "Your password has been successfully updated.")
                            break
                        else:
                            messagebox.showwarning("Weak Password",
                                                   "The password is too weak. Please choose a stronger password.")
                    else:
                        messagebox.showwarning("Input Error", "Password cannot be empty.")
                        return
            else:
                messagebox.showerror("Invalid Token", "The recovery token is invalid.")
        else:
            messagebox.showerror("Error", "The email provided does not match our records.")
    else:
        messagebox.showerror("Error", "User not found.")

def update_password_change_date():
    # Get the current timestamp
    current_timestamp = datetime.now().isoformat()

    # Write the timestamp to the file
    with open(LAST_CHANGE_FILE, 'w') as file:
        file.write(current_timestamp)

def check_password_update_needed():
    if os.path.exists(LAST_CHANGE_FILE):
        with open(LAST_CHANGE_FILE, 'r') as file:
            last_change = datetime.fromisoformat(file.read().strip())
        if datetime.now() > last_change + timedelta(days=365):
            messagebox.showinfo("Password Update", "It has been over a year since your last password change. Please update your password.")
    else:
        initialize_password_change_file()



def send_recovery_email(email, token):
    sender_email = os.getenv('EMAIL_USER')
    sender_password = os.getenv('EMAIL_PASS')
    subject = "Password Recovery"
    body = f"Your password recovery token is: {token}"

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, email, msg.as_string())
        server.quit()
        messagebox.showinfo("Success", "Recovery email sent successfully.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to send email: {str(e)}")

def generate_recovery_token():
    """Generates a random 6-digit token for password recovery"""
    token = ''.join(random.choices(string.digits, k=6))
    return token


# GUI Functions
def setup_menu(root):
    menubar = Menu(root)

    # User Management Menu
    user_menu = Menu(menubar, tearoff=0)
    user_menu.add_command(label="Add User", command=add_user)
    user_menu.add_command(label="View Password", command=view_password)
    user_menu.add_command(label="Delete User", command=delete_user)
    user_menu.add_command(label="Change Password", command=recover_password)
    menubar.add_cascade(label="User Management", menu=user_menu)

    root.config(menu=menubar)


def initialize_password_change_file():
    """
    Initializes the password change file and notifies the user if the file is newly created.
    The notification will only appear once when the file is first created.
    """
    if not os.path.exists(LAST_CHANGE_FILE):
        # Notify user and create the file with the current timestamp
        messagebox.showinfo("Password Update",
                            "It has been over a year since your last password change. Please update your password.")
        with open(LAST_CHANGE_FILE, 'w') as file:
            file.write(datetime.now().isoformat())


def check_password_update_needed():
    """
    This function will only be responsible for managing updates based on the file's timestamp.
    It will not handle the first-run notification logic.
    """
    if os.path.exists(LAST_CHANGE_FILE):
        with open(LAST_CHANGE_FILE, 'r') as file:
            last_change = datetime.fromisoformat(file.read().strip())
        if datetime.now() > last_change + timedelta(days=365):
            # Notify user to change their password
            messagebox.showinfo("Password Update",
                                "It has been over a year since your last password change. Please update your password.")

            # Update the file with the new timestamp after notifying
            with open(LAST_CHANGE_FILE, 'w') as file:
                file.write(datetime.now().isoformat())


# GUI Initialization
root = tk.Tk()
root.title("Password Management")
root.geometry("600x400")  # Set width=600, height=400
root.resizable(True, True)  # Allow resizing both horizontally and vertically

# Add a frame for better layout management
frame = tk.Frame(root, padx=20, pady=20)
frame.pack(fill="both", expand=True)

# Instruction text for users
instructions = (
    "Welcome to the Password Manager!\n\n"
    "• To get started, please create a user account.\n"
    "• A strong password must be at least 8 characters long, "
    "with uppercase, lowercase, numbers, and special characters."
)
tk.Label(
    frame, text=instructions, wraplength=550, justify="left", fg="blue", font=("Arial", 12)
).grid(row=0, column=0, columnspan=2, pady=20)

# Setup menu
setup_menu(root)

# Check if file exists or needs a notification
initialize_password_change_file()  # Notify user only when creating the file
check_password_update_needed()  # Handle further checks for the file

# Run the application
root.mainloop()
