import os
import socket
import ssl
import configparser
import time
from datetime import datetime
from dotenv import load_dotenv

# Configuration
HOST = "127.0.0.1"  # Server IP address (localhost)
PORT = 12345  # Server port

USE_SSL = False  # Flag to indicate whether to use SSL
PSK = None  # Pre-shared key if using PSK

# Get the env variable
load_dotenv()

# Load the config file
CONFIG_FILE = os.getenv("CONFIG")

# Load the config file
config = configparser.ConfigParser()
config.read(CONFIG_FILE)

# Test queries
TEST_QUERIES = [
    "line1", "line2", "exactmatch", "+279;", "nonexistent",
    "7;0;6;28;0;9;4;0;", "7;0;6;28", "300000;", "Tobenna;", "Iloabuchi;",
    "Ilo;", "TBAG", "line3", "22245;", "278;", "279;", "28794137;", "+233;",
    "12;0;6;21;0;17;4;0;", "23;0;6;26;0;10;3;0;", "13;0;23;28;0;19;3;0;",
    "TOBEX", "tti", "TIT", "tobexint", "norse", "algae", "ZINC", "TRUST",
    "ENAMEL", "10;0;1;16;0;13;3;0;", "NNAMDI;", "CHIEF", "meat "
]


def create_ssl_context():
    """
    Creates and returns an SSL context if SSL is enabled.
    """
    if not USE_SSL:
        return None

    # Retrieve the certfile and keyfile for ssl authentication
    certfile = config.get('DEFAULT', 'CERTFILE')
    keyfile = config.get('DEFAULT', 'KEYFILE')

    if not certfile or not keyfile:
        raise ValueError("CERTFILE and KEYFILE "
                         "must be defined in the config file.")

    try:
        # Create an ssl context
        context = ssl.create_default_context()

        # Verify certfile location
        context.load_verify_locations(certfile)

        # Load ssl cert and key files
        context.load_cert_chain(certfile, keyfile)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_REQUIRED

        return context

    except ssl.SSLError as e:
        print(f"ERROR: Failed to create SSL context - {e}")
        return None


def send_request(query: str) -> str:
    """
    Sends a request to the server with optional SSL encryption.
    """
    context = create_ssl_context()

    try:
        # Create a connection to the server
        with socket.create_connection((HOST, PORT)) as sock:
            start_time = time.time()

            # If SSL is enabled, wrap the socket in the SSL context
            if context:
                try:
                    with context.wrap_socket(
                            sock, server_hostname=HOST) as ssock:
                        print(
                            f"DEBUG [{datetime.now()}] -"
                            f"Sending query: '{query}' "
                            f"to {HOST}:{PORT}"
                            )
                        ssock.sendall(query.encode("utf-8"))
                        response = ssock.recv(1024).decode("utf-8")
                except ssl.SSLError as e:
                    print(f"ERROR: SSL handshake failed - {e}")
                    return "SSL HANDSHAKE ERROR"
            else:
                print(
                    f"DEBUG [{datetime.now()}] - Sending query: '{query}' "
                    f"to {HOST}:{PORT}"
                    )
                sock.sendall(query.encode("utf-8"))
                response = sock.recv(1024).decode("utf-8")

            end_time = time.time()
            execution_time = end_time - start_time
            print(
                f"DEBUG [{datetime.now()}] - Response: '{response.strip()}' | "
                f"Execution Time: {execution_time:.6f}s"
                )

            return response

    except ConnectionResetError:
        print(f"ERROR: Connection was forcibly closed by {HOST}:{PORT}")
        return "CONNECTION RESET ERROR"

    except ConnectionRefusedError:
        print(f"ERROR: Server at {HOST}:{PORT} refused connection.")
        return "CONNECTION REFUSED"

    except socket.timeout:
        print(f"ERROR: Connection to {HOST}:{PORT} timed out.")
        return "CONNECTION TIMEOUT"

    except socket.error as e:
        print(f"ERROR: Socket error - {e}")
        return "SOCKET ERROR"

    except KeyboardInterrupt:
        print("\nClient interrupted. Exiting gracefully...")
        exit(0)  # Exit the program cleanly

    except Exception as e:
        print(f"ERROR: Unexpected error - {e}")
        return "UNKNOWN ERROR"


if __name__ == "__main__":
    for query in TEST_QUERIES:
        response = send_request(query)
        print(f"Query: '{query}' - Response: {response}")
