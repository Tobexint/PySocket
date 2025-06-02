import socket
import ssl
import subprocess
import time


def send_query(query, port, results, index):
    """Send a plain text query to the server and store the response."""
    try:
        with socket.create_connection(("localhost", port), timeout=2) as sock:
            sock.sendall((query + "\n").encode())
            response = sock.recv(1024).decode().strip()
            results[index] = response
    except Exception as e:
        results[index] = f"ERROR: {e}"


def send_query_ssl(query, port, results, index, cafile):
    """Send a query to an SSL-enabled server and store the response."""
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=cafile)
    try:
        with socket.create_connection(("localhost", port), timeout=2) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname="localhost") as sock:
                sock.sendall((query + "\n").encode())
                response = sock.recv(1024).decode().strip()
                results[index] = response
    except Exception as e:
        results[index] = f"SSL ERROR: {e}"


def generate_self_signed_cert(cert_path, key_path):
    """Generate a temporary self-signed SSL certificate and key using OpenSSL."""
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256",
        "-days", "1", "-nodes",
        "-subj", "/CN=localhost",
        "-keyout", key_path,
        "-out", cert_path
    ], check=True)


# Helper function to find a free port.
def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('localhost', 0))
        return s.getsockname()[1]


def send_query_with_retries(query, port, results, idx):
        for _ in range(3):
            try:
                with socket.create_connection(('localhost', port), timeout=3) as s:
                    s.sendall(query.encode())
                    results[idx] = s.recv(1024).decode()
                    return

            except Exception as e:
                results[idx] = f"ERROR: {e}"
                time.sleep(0.2)
