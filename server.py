import socket
import platform
import sys
import threading
import time
import configparser
import ssl
import os
from typing import Tuple, Set
from dotenv import load_dotenv


# Get the env variables
load_dotenv()

# Load the config file
CONFIG_FILE = os.getenv("CONFIG")

# Get the directory where the current script lives
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Read the config file
config = configparser.ConfigParser()
config.read(os.path.join(BASE_DIR, CONFIG_FILE))

# Global variable to hold preloaded lines as a hash set
preloaded_set = set()


# Function to load configuration from a file
def load_config(file_path: str) -> Tuple[str, bool, bool, str, str, str, int]:
    """
    Reads and loads server configuration from a config file.
    """

    try:
        # Retrieve the 'linuxpath' value from the 'DEFAULT' section,
        # or set it to None if not found
        linuxpath = os.path.join(BASE_DIR, config['DEFAULT']['linuxpath'])

        # Retrieve 'REREAD_ON_QUERY' as a boolean from the 'DEFAULT' section,
        # defaulting to False if not found
        reread_on_query = config.getboolean('DEFAULT',
                                            'REREAD_ON_QUERY', fallback=False)

        # Retrieve 'USE_SSL' as a boolean from the 'DEFAULT' section,
        # defaulting to False if not found
        use_ssl = config.getboolean('DEFAULT', 'USE_SSL', fallback=False)

        # Retrieve the SSL certificate file path from the 'DEFAULT' section,
        # defaulting to None if not found
        certfile = os.path.join(BASE_DIR, config['DEFAULT']['CERTFILE'])

        # Retrieve the SSL key file path from the 'DEFAULT' section,
        # defaulting to None if not found
        keyfile = os.path.join(BASE_DIR, config['DEFAULT']['KEYFILE'])

        # Retrieve the pre-shared key (PSK) from the 'DEFAULT' section,
        # defaulting to None if not found
        psk = config.get('DEFAULT', 'PSK', fallback=None)

        # Retrieve the 'PORT' value as an integer from the 'DEFAULT' section,
        # defaulting to 12345 if not found
        port = config.getint('DEFAULT', 'PORT', fallback=12345)

        # Ensure the file path exists
        if not os.path.isfile(linuxpath):
            raise FileNotFoundError(f"The file {linuxpath} is not found.")

        """Validate configuration values"""
        if use_ssl and (not certfile or not keyfile):
            raise ValueError("SSL is enabled in the configuration,"
                             "but either the certificate or"
                             "key file is not provided.")

        """Return the configuration values"""
        return (
            linuxpath, reread_on_query, use_ssl,
            certfile, keyfile, psk, port
            )

    except configparser.NoSectionError as e:
        raise RuntimeError(f"Error reading config file '{CONFIG_FILE}': "
                           f"Section not found - {e.section}")

    except configparser.NoOptionError as e:
        raise RuntimeError(f"Error reading config file '{CONFIG_FILE}': "
                           f"Option not found in the section [{e.section}]"
                           f"- {e.option}")

    except ValueError as e:
        raise RuntimeError(f"Invalid value in config file "
                           f"'{CONFIG_FILE}': {e}")

    except FileNotFoundError as e:
        raise RuntimeError(f"Error accessing a configured file: {e}")

    except OSError as e:
        raise RuntimeError(f"Operating system error while accessing config "
                           f"file '{CONFIG_FILE}': {e}")

    except Exception as e:
        raise RuntimeError(f"An unexpected error occurred while loading"
                           f"configuration from '{CONFIG_FILE}': {e}")


# Function to read file into a hash set
def load_file_into_set(filepath: str) -> Set[str]:
    """
    Reads a file and stores each line as an entry in a set for quick lookup.
    """
    try:
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File '{filepath}' does not exist.")

        if not os.path.isfile(filepath):
            raise IsADirectoryError(f"'{filepath}'"
                                    "is a directory, not a file.")

        # Open the file specified by 'filepath' in read mode ('r')
        with open(filepath, 'r', encoding='utf-8') as file:
            """ Read each line from the file, strip leading/trailing
            whitespace,and store the unique lines in a set. """
            return {line.strip() for line in file if line.strip()}

    except FileNotFoundError as e:
        raise FileNotFoundError(f"Error: File '{filepath}' not found: {e}")

    except PermissionError:
        raise PermissionError(
                f'Permission denied while reading the file: {filepath}')

    except UnicodeDecodeError as e:
        raise UnicodeDecodeError("utf-8", b"", 0, 1,
                                 f"Error: Failed to decode file: "
                                 f"'{filepath}' using UTF-8: {e}")
    except OSError as e:
        if isinstance(e, IsADirectoryError):
            raise IsADirectoryError(f"'{filepath}'"
                                    "is a directory, not a file.")

        raise RuntimeError(f"Operating system error while reading data file "
                           f"'{filepath}': {e}")

    except Exception as e:
        raise RuntimeError(
                f"An unexpected error occurred while "
                f"reading the file '{filepath}': {e}"
                )


# Function to search for a string using a hash set
def search_string_in_set(lines_set: Set[str], search_string: str) -> bool:
    """
    Searches for the given string in the preloaded set.
    """
    return search_string.strip() in lines_set


# Function to handle a client connection
def handle_client(client_socket: socket.socket, address: Tuple[str, int],
                  linuxpath: str, reread_on_query: bool):
    """
    Handles an individual client connection.
    """

    # Record the start time for performance measurement
    start_time = time.time()

    try:
        # Receive and decode the query from the client
        request = client_socket.recv(1024).decode('utf-8').strip()

        # Check if the '\x00' character is present in the request string
        if '\x00' in request:
            # Remove all occurrences of the '\x00
            # character from the request string
            request = request.replace('\x00', '')

        # Check if the length of the request exceeds 200 characters
        if len(request) > 200:

            # Send an error message in bytes format
            # to the client indicating the query is too long
            client_socket.sendall(b"ERROR: Query too long\n")

            # Close the client socket to terminate the connection
            client_socket.close()

            # Exit the function to prevent further
            # processing of the oversized request
            return

        # Reload file if reread_on_query is enabled, else use preloaded set
        if reread_on_query:
            print("DEBUG: reread_on_query is True, reading file again...")
            try:
                # Attempt to load the contents of the file
                # specified by 'linuxpath' into a set
                lines_set = load_file_into_set(linuxpath)

            # Handle exceptions if the file is not found (FileNotFoundError)
            # or there's an input/output error (IOError)
            except FileNotFoundError:
                error_message = b"ERROR: File not found on the server\n"
                print(f"ERROR: {error_message.decode().strip()}")
                client_socket.sendall(error_message)
                return

            except OSError as e:
                error_message = (b"ERROR: Operating system error "
                                 b"reading data file\n")
                print(f"ERROR: {error_message.decode().strip()}: {e}")
                client_socket.sendall(error_message)
                return

            except Exception as e:
                error_message = b"ERROR: Server error reading data file\n"
                print(f"ERROR: {error_message.decode().strip()}: {e}")
                client_socket.sendall(error_message)

                # Exit the function to prevent further execution
                return
        else:
            print("DEBUG: reread_on_query is False, using preloaded lines")
            lines_set = preloaded_set

        # Search for the string in the hash set
        string_exists = search_string_in_set(lines_set, request)

        # Return the response
        if string_exists:
            response = 'STRING EXISTS\n'
        else:
            response = 'STRING NOT FOUND'

        # Send response to the client
        client_socket.sendall(response.encode('utf-8'))

        # Record the end time
        end_time = time.time()

        # Calculate the execution times
        execution_time = end_time - start_time

    except ConnectionResetError:
        print(f"WARNING: Connection reset by client {address}")

    except socket.timeout:
        print(f"WARNING: Socket timeout with client {address}")
        client_socket.sendall(b"ERROR: Connection timed out\n")

    except socket.error as e:
        print(f"ERROR: Socket error with {address}: {e}")
        client_socket.sendall(b"ERROR: Network error\n")

    except UnicodeDecodeError:
        print(f"ERROR: Unable to decode message from {address}")
        client_socket.sendall(b"ERROR: Invalid message encoding\n")

    except Exception as e:
        print(f"ERROR: Unexpected error handling client {address}: {e}")
        client_socket.sendall(b"ERROR: Server encountered "
                              b"an unexpected error\n")

    finally:
        client_socket.close()

        # Log the query, string, and execution times
        print(
            f"Query from {address[0]}:{address[1]} - "
            f"String: '{request}' - "
            f"Found: {string_exists} - "
            f"Execution Time: {execution_time:.6f} seconds"
            )


# Function to start the server
def start_server(linuxpath: str, reread_on_query: bool, use_ssl: bool,
                 certfile: str, keyfile: str, psk: str, port: int):
    """
    Starts the server, listens for incoming client connections.
    """

    # A global variable
    global preloaded_set

    # Preload file contents into a hash set if reread_on_query is disabled
    if not reread_on_query:
        try:
            preloaded_set = load_file_into_set(linuxpath)

        except FileNotFoundError as e:
            print(f"ERROR: Failed to preload data file '{linuxpath}': {e}")
            sys.exit(1)

        except OSError as e:
            print(f"ERROR: Operating system error while preloading data file "
                  f"'{linuxpath}': {e}")
            sys.exit(1)

        except Exception as e:
            print(f"ERROR: Unexpected error during data file preloading "
                  f"'{linuxpath}': {e}")
            sys.exit(1)

    try:
        # Create a TCP socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Allow reuse of the socket address
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Bind the socket to all available interfaces on the specified port
        server_socket.bind(('0.0.0.0', port))

        # Listen for incoming connections with a backlog of 100
        server_socket.listen(100)

        # Enable SSL if configured
        if use_ssl:
            try:
                # Create an SSL context for a TLS server,
                # which manages secure communication
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                if certfile and keyfile:
                    # Load the SSL certificate and key
                    try:
                        context.load_cert_chain(certfile, keyfile)

                    except FileNotFoundError as e:
                        print(f"ERROR: SSL certificate or "
                              f"key file not found: {e}")
                        return  # Exit if SSL setup fails

                    except ssl.SSLError as e:
                        print(f"ERROR: Error loading SSL certificate or "
                              f"key: {e}")
                        return  # Exit if SSL setup fails

                # Wrap the server socket with SSL
                server_socket = context.wrap_socket(server_socket,
                                                    server_side=True)
                print("SSL enabled")

            except ssl.SSLError as e:
                print(f"ERROR: Failed to initialize SSL: {e}")
                return  # Exit if SSL setup fails

            except Exception as e:
                print(f"ERROR: Unexpected error during "
                      f"SSL initialization: {e}")
                return  # Exit if SSL setup fails

        # Print a message indicating the server has started
        print(f"Server started on port {port}")

        while True:
            # Accept incoming client connection
            client_socket, address = server_socket.accept()

            # Create a new thread to handle the client connection
            client_handler = threading.Thread(
                    target=handle_client,
                    args=(client_socket, address, linuxpath, reread_on_query)
            )

            # Start a thread for each new client connection
            client_handler.start()

    except socket.error as e:
        print(f"Socket error while starting or running the server: {e}")

    except ssl.SSLError as e:
        print(f"SSL error during server operation: {e}")

    except OSError as e:
        print(f"Operating system error during server operation: {e}")

    except KeyboardInterrupt:
        print("Server shutting down.")

    finally:
        try:
            server_socket.close()

        except socket.error as e:
            print(f"Error closing server socket: {e}")


# Function to run as a linux daemon
def daemonize():
    """Fork to run in background."""
    if os.fork():
        sys.exit()
    os.setsid()
    if os.fork():
        sys.exit()
    sys.stdout.flush()
    sys.stderr.flush()


# Main script execution
if __name__ == "__main__":
    is_windows = platform.system() == "Windows"

    if '--daemon' in sys.argv:
        if not is_windows:
            try:
                daemonize()
                (
                    linuxpath, reread_on_query, use_ssl,
                    certfile, keyfile, psk, port
                ) = load_config(config)  # Pass the configuration file

                start_server(
                    linuxpath, reread_on_query, use_ssl,
                    certfile, keyfile, psk, port
                    )
            except RuntimeError as e:
                print(f"Server failed to start due "
                      f"to a configuration error: {e}")
                sys.exit(1)

            except Exception as e:
                print(f"Server failed to start due "
                      f"to an unexpected error: {e}")
                sys.exit(1)
        else:
            print("Daemon mode is not supported on Windows."
                  "Running in foreground.")
    else:
        try:
            # Load server configuration
            (
                linuxpath, reread_on_query, use_ssl,
                certfile, keyfile, psk, port
            ) = load_config(config)
        except RuntimeError as e:
            print(f"Error loading configuration: {e}")
            sys.exit(1)

        except Exception as e:
            print(f"An unexpected error occurred during "
                  f"configuration loading: {e}")
            sys.exit(1)

    # Start the server with the loaded configuration
    start_server(
        linuxpath, reread_on_query, use_ssl,
        certfile, keyfile, psk, port
    )
