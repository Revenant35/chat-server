import argparse
import logging
import socket
import threading

logging.basicConfig(level=logging.WARN)

should_run = threading.Event()
should_run.set()

logged_in = threading.Event()
logged_in.clear()


def is_valid_username(username):
    return 3 <= len(username) <= 32


def is_valid_password(password):
    return 4 <= len(password) <= 8


def is_valid_message(message):
    return 1 <= len(message) <= 256


def validate_command(command):
    split_command = command.split()
    if logged_in.is_set():
        # While logged in, a user should be able to
        #   send <"all"/<user>> <message>
        #   who
        #   logout
        if command.startswith("send all "):  # send all <message>
            if not len(split_command) >= 3:
                return False
            _, _, *message = split_command
            return is_valid_message(message)
        elif command.startswith("send "):  # send <user> <message>
            if not len(split_command) >= 3:
                return False
            _, user, *message = split_command
            return is_valid_username(user) and is_valid_message(message)
        elif command == "who" or command == "logout":
            return True
        return False

    else:
        # While logged out, a user should only be able to
        #  login <user> <password>
        #  newuser <user> <password>
        if command.startswith("login "):
            if not len(split_command) == 3:
                return False
            _, user, password = split_command
            return is_valid_username(user) and is_valid_password(password)
        elif command.startswith("newuser "):
            if not len(split_command) == 3:
                return False
            _, user, password = split_command
            return is_valid_username(user) and is_valid_password(password)
        return False


def receive_message(client_socket):
    while should_run.is_set():
        try:
            message = client_socket.recv(1024).decode("utf-8")
        except ConnectionError:
            logging.warning("Server disconnected.")
            should_run.clear()
            exit(1)
        if message:
            print(message)
        if message == "Login successful.":
            logged_in.set()


def main():
    # Set up client socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:  # Try to connect to the server
        client_socket.connect(("127.0.0.1", 19735))
    except ConnectionRefusedError:
        logging.critical("Server is not running.")
        exit(1)

    # Receive the server's response, which will either be "accepted" or "rejected"
    status = client_socket.recv(1024).decode("utf-8")
    if status == "rejected":
        logging.critical("Connection rejected. Server is full.")
        exit(1)

    # Start a thread to receive messages from the server
    receive_thread = threading.Thread(target=receive_message, args=(client_socket,))
    receive_thread.daemon = True  # Ensure the thread exits when the main program does.
    receive_thread.start()

    while should_run.is_set():
        command = input()

        if not validate_command(command):
            logging.warning("Invalid command or parameters. Try again.")
            continue

        try:
            client_socket.send(command.encode("utf-8"))
        except ConnectionError:
            logging.warning("Server disconnected.")
            exit(1)

        if command == "logout":
            exit(0)

    client_socket.close()


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
