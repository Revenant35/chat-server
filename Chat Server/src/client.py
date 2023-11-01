import argparse
import logging
import socket

logging.basicConfig(level=logging.WARN)


def is_valid_username(username):
    return 3 <= len(username) <= 32 and username not in ["SERVER", "all"]


def is_valid_password(password):
    return 4 <= len(password) <= 8


def is_valid_message(message):
    return 1 <= len(message) <= 256


def validate_command(command, logged_in):
    if logged_in:
        # While logged in, a user should be able to
        #   send <message>
        #   logout
        if command.startswith("send "):  # send <message>
            if not len(command.split()) >= 2:
                return False
            _, *message = command.split(" ", 1)
            return is_valid_message(message)
        elif command == "logout":  # logout
            return True
        return False

    else:
        # While logged out, a user should only be able to
        #  login <user> <password>
        #  newuser <user> <password>
        if command.startswith("login "):  # login <user> <password>
            if not len(command.split()) == 3:
                return False
            _, user, password = command.split()
            return is_valid_username(user) and is_valid_password(password)
        elif command.startswith("newuser "):  # newuser <user> <password>
            if not len(command.split()) == 3:
                return False
            _, user, password = command.split()
            return is_valid_username(user) and is_valid_password(password)
        return False


def main():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.settimeout(5)

    try:
        client_socket.connect(("127.0.0.1", 19735))
    except ConnectionError:
        logging.critical("Server refused your connection or is not running.")
        exit(1)
    except socket.timeout:
        logging.critical("Server is not responding.")
        exit(1)

    # Receive the server's response, which will either be "accepted" or "rejected"
    status = client_socket.recv(1024).decode("utf-8")
    if status == "rejected":
        logging.critical("Connection rejected. Server is full.")
        exit(1)

    logged_in = False
    while True:
        command = input()

        if not validate_command(command, logged_in):
            logging.warning("Invalid command or parameters. Try again.")
            continue

        try:
            client_socket.send(command.encode("utf-8"))
        except ConnectionError:
            logging.warning("Server disconnected.")
            exit(1)

        if command == "logout":
            exit(0)

        try:
            response = client_socket.recv(1024).decode("utf-8")
        except ConnectionError:
            logging.warning("Server disconnected.")
            exit(1)

        if command.startswith("login ") and response == "Login successful.":
            logged_in = True

        print(response)


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
