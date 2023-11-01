import socket
import threading
import logging
import os
import argparse

logging.basicConfig(level=logging.WARN)

USERS_FILE = "users.txt"
USERS = {}
ACTIVE_USERS = {}
MAX_CLIENTS = 3
LOCK = threading.Lock()
current_clients = 0

banned_names = ["SERVER", "all"]


def is_valid_username(username):
    return 3 <= len(username) <= 32 and username not in banned_names


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


# Broadcast a message to all users from a specific user
def broadcast_client_message(sender, message):
    logging.info(f"{sender} [all]: {message}")
    for user, sock in ACTIVE_USERS.items():
        sock.send(f"{sender} [all]: {message}".encode("utf-8"))


# Broadcast a message to all users from the server
def broadcast_server_message(message):
    logging.info(f"SERVER [all]: {message}")
    for _, sock in ACTIVE_USERS.items():
        sock.send(f"SERVER [all]: {message}".encode("utf-8"))


# Send a private message from one user to another user
def send_client_message(sender, receiver, message):
    logging.info(f"{sender} [{receiver}]: {message}")
    ACTIVE_USERS[receiver].send(f"{sender} [{receiver}]: {message}".encode("utf-8"))
    if sender != receiver:
        ACTIVE_USERS[sender].send(f"{sender} [{receiver}]: {message}".encode("utf-8"))


# Send a private message from the server to a user
def send_server_message(receiver, message):
    logging.info(f"SERVER [{receiver}]: {message}")
    ACTIVE_USERS[receiver].send(f"SERVER: {message}".encode("utf-8"))


# Handle a client connection
def handle_client(client_socket):
    global current_clients
    user_logged_in = None

    while True:
        try:
            # wait for user input
            command = client_socket.recv(1024).decode("utf-8")
        except ConnectionResetError:
            # Client closed the connection
            logging.info(
                f"Connection unexpectedly closed from {client_socket.getpeername()}"
            )
            if user_logged_in is not None:
                with LOCK:
                    ACTIVE_USERS.pop(user_logged_in, None)
                    logging.info(f"{user_logged_in} logged out.")
                    broadcast_server_message(f"{user_logged_in} left.")
            break
        except Exception as e:
            # Likely, client closed the connection without logging out
            logging.warning(f"Exception: {e}")
            if user_logged_in is not None:
                logging.info(f"{user_logged_in} logged out.")
                broadcast_server_message(f"{user_logged_in} logged out.")
            break

        if not command:
            # Client closed the connection
            logging.info(f"Connection closed from {client_socket.getpeername()}")
            if user_logged_in is not None:
                with LOCK:
                    ACTIVE_USERS.pop(user_logged_in, None)
                logging.info(f"{user_logged_in} logged out.")
                broadcast_server_message(f"{user_logged_in} logged out.")
            break

        if user_logged_in:
            if command == "logout":
                with LOCK:
                    ACTIVE_USERS.pop(user_logged_in, None)
                logging.info(f"{user_logged_in} logged out.")
                broadcast_server_message(f"{user_logged_in} left.")
                client_socket.close()
                break

            if command == "who":
                users_list = ", ".join(ACTIVE_USERS.keys())
                client_socket.send(users_list.encode("utf-8"))
                continue

            if command.startswith("send all "):  # send all <message>
                if not len(command.split()) >= 3:
                    client_socket.send("Invalid input.".encode("utf-8"))
                    continue
                _, _, message = command.split(" ", 2)
                broadcast_client_message(user_logged_in, message)
                continue

            if command.startswith("send "):  # send <user> <message>
                if not len(command.split()) >= 3:
                    client_socket.send("Invalid input.".encode("utf-8"))
                    continue
                _, target_user, message = command.split(" ", 2)
                if target_user in ACTIVE_USERS:
                    send_client_message(user_logged_in, target_user, message)
                    continue
                else:
                    client_socket.send("User not found.".encode("utf-8"))
                    continue
        else:
            if command.startswith("login "):  # login <user> <password>
                split_command = command.split()
                if not len(split_command) == 3:
                    client_socket.send("Invalid input.".encode("utf-8"))
                    continue
                _, user, password = split_command
                # Note: we don't need to check for validity and banned names here, but it's good to be paranoid
                if not is_valid_username(user) or not is_valid_password(password):
                    client_socket.send("Invalid input.".encode("utf-8"))
                    continue
                if USERS.get(user) == password and user not in ACTIVE_USERS:
                    user_logged_in = user
                    broadcast_server_message(f"{user_logged_in} joined.")
                    with LOCK:
                        ACTIVE_USERS[user] = client_socket
                    client_socket.send("Login successful.".encode("utf-8"))
                    continue
                else:
                    client_socket.send("Login failed.".encode("utf-8"))
                    continue

            if command.startswith("newuser "):  # newuser <user> <password>
                split_command = command.split()
                if not len(split_command) == 3:  # Check for valid input
                    client_socket.send("Invalid/Missing parameters.".encode("utf-8"))
                    continue
                _, user, password = split_command
                if not is_valid_username(user) or not is_valid_password(password):
                    client_socket.send("Invalid username or password.".encode("utf-8"))
                    continue
                if user not in USERS:
                    USERS[user] = password
                    with open(USERS_FILE, "a") as file:
                        file.write(f"\n{user},{password}")
                    client_socket.send("User created successfully.".encode("utf-8"))
                    continue
                else:
                    client_socket.send("User already exists.".encode("utf-8"))
                    continue

        client_socket.send("Invalid command.".encode("utf-8"))
    with LOCK:
        current_clients -= 1


def main():
    global current_clients
    load_users()

    # Initialize the server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("127.0.0.1", 19735))
    server_socket.settimeout(1)  # Set a timeout of 1 second
    server_socket.listen(MAX_CLIENTS)
    logging.info("Server listening on port 19735...")

    # Event Loop
    while True:
        # Accept all connections from clients
        try:
            client_socket, addr = server_socket.accept()
        except socket.timeout:
            continue
        logging.info(f"Connection made from: {client_socket.getpeername()}")

        # Check if we're under the MAXCLIENTS limit
        with LOCK:
            if (
                current_clients < MAX_CLIENTS
            ):  # If we're under the limit, accept the connection
                current_clients += 1
                logging.info(f"Current clients: {current_clients}")
                client_socket.send("accepted".encode("utf-8"))
            else:  # otherwise, reject the connection
                client_socket.send("rejected".encode("utf-8"))
                client_socket.close()
                logging.info(f"Connection pool is full; rejecting {addr}")
                continue

        # Start a new thread to handle the client
        client_thread = threading.Thread(target=handle_client, args=(client_socket,))
        client_thread.daemon = True
        client_thread.start()


if __name__ == "__main__":
    # Define argument parser
    parser = argparse.ArgumentParser(description="Set logging level based on argument.")
    parser.add_argument(
        "-l",
        "--loglevel",
        help="Set log level (e.g., DEBUG, INFO, WARNING, ERROR, CRITICAL)",
        default="INFO",
    )

    # Parse the arguments
    args = parser.parse_args()

    # Convert the log level string to an actual log level
    numeric_level = getattr(logging, args.loglevel.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {args.loglevel}")

    # Configure logging
    logging.basicConfig(level=numeric_level)

    main()
