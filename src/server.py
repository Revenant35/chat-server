import os
import socket

USERS_FILE = "users.txt"
USERS = {}


def is_valid_username(username):
    return 3 <= len(username) <= 32 and username not in ["SERVER", "all"]


def is_valid_password(password):
    return 4 <= len(password) <= 8


def is_valid_message(message):
    return 1 <= len(message) <= 256


def load_users():
    # Create the users file if it doesn't exist
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, "w") as file:
            file.write("Tom,Tom11")
            file.write("\nDavid,David22")
            file.write("\nBeth,Beth33")

    # Load the users from the file into the USERS dictionary
    with open(USERS_FILE, "r") as file:
        for line in file:
            user, password = line.strip().split(",")
            if is_valid_username(user) and is_valid_password(password):
                USERS[user] = password


def handle_client(client_socket):
    user_logged_in = None

    while True:
        try:
            command = client_socket.recv(1024).decode("utf-8")
        except ConnectionError or Exception:
            # Client closed the connection
            print(f"Connection unexpectedly closed from {client_socket.getpeername()}")
            if user_logged_in is not None:
                print(f"{user_logged_in} logged out.")
            break

        if not command:
            # Client closed the connection
            print(f"Connection closed from {client_socket.getpeername()}")
            if user_logged_in is not None:
                print(f"{user_logged_in} logged out.")
            break

        if user_logged_in is not None:  # User is logged in
            if command == "logout":
                print(f"{user_logged_in} logged out.")
                client_socket.close()
                break

            if command.startswith("send "):
                if not len(command.split()) >= 2:
                    client_socket.send("Invalid input.".encode("utf-8"))
                    continue
                _, message = command.split(" ", 1)
                print(f"{user_logged_in}: {message}")
                client_socket.send(f"{user_logged_in}: {message}".encode("utf-8"))
                continue

        else:  # User is not logged in
            if command.startswith("login "):
                if not len(command.split()) == 3:
                    client_socket.send("Invalid input.".encode("utf-8"))
                    continue
                _, user, password = command.split()
                # Note: we don't need to check for validity and banned names here, but it's good to be paranoid
                if not is_valid_username(user) or not is_valid_password(password):
                    client_socket.send("Invalid input.".encode("utf-8"))
                    continue
                if USERS.get(user) == password:
                    user_logged_in = user
                    print(f"{user} logged in successfully.")
                    client_socket.send("Login successful.".encode("utf-8"))
                    continue
                else:
                    client_socket.send("Login failed.".encode("utf-8"))
                    continue

            if command.startswith("newuser "):
                if not len(command.split()) == 3:
                    client_socket.send("Invalid input.".encode("utf-8"))
                    continue
                _, user, password = command.split()
                if not is_valid_username(user) or not is_valid_password(password):
                    client_socket.send("Invalid username or password.".encode("utf-8"))
                    continue
                if user not in USERS:
                    USERS[user] = password
                    with open(USERS_FILE, "a") as file:
                        file.write(f"\n{user},{password}")
                    print(f"User {user} created successfully.")
                    client_socket.send("User created successfully.".encode("utf-8"))
                    continue
                else:
                    client_socket.send("User already exists.".encode("utf-8"))
                    continue

        client_socket.send("Invalid command.".encode("utf-8"))


def main():
    global CLIENT_SOCKET
    load_users()

    # Initialize the server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("127.0.0.1", 19735))
    server_socket.settimeout(1)  # Set a timeout of 1 second
    server_socket.listen(1)
    print("Server listening on port 19735...")

    # Event Loop
    while True:
        # Accept all connections from clients
        try:
            client_socket, addr = server_socket.accept()
        except socket.timeout:
            continue

        print(f"Connection made from: {client_socket.getpeername()}")

        client_socket.send("accepted".encode("utf-8"))

        handle_client(client_socket)


if __name__ == "__main__":
    main()
