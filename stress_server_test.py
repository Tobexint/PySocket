import socket
import threading
import time

# Server configuration
HOST = "127.0.0.1"  # Change to server IP if needed
PORT = 12345  # Ensure this matches your server config
NUM_THREADS = 100  # Number of concurrent clients
NUM_REQUESTS = 1000  # Requests per thread

# Test query strings
QUERIES = ["test_line_1", "test_line_5000", "nonexistent", "test_line_999999", "TRUST", "NNAMDI;", "CHIEF"]


def send_query(query):
    """
    Sends a query to the server and measures response time.
    """
    try:
        with socket.create_connection((HOST, PORT)) as sock:
            start_time = time.time()
            sock.sendall(query.encode("utf-8"))
            response = sock.recv(1024).decode("utf-8")
            end_time = time.time()

            latency = end_time - start_time
            print(f"Query: '{query}' | Response: '{response.strip()}' | Latency: {latency:.6f} sec")

    except ConnectionRefusedError:
        print("Server is not accepting connections.")
    except Exception as e:
        print(f"Error: {e}")


def execute_queries():
    """
    Runs NUM_REQUESTS queries for each item in QUERIES.
    """
    for _ in range(NUM_REQUESTS):
        for query in QUERIES:
            send_query(query)


def stress_test():
    """
    Spawns multiple threads to simulate high query load on the server.
    """
    threads = []
    start_time = time.time()

    for _ in range(NUM_THREADS):
        thread = threading.Thread(target=execute_queries)
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    end_time = time.time()
    total_time = end_time - start_time
    total_queries = NUM_THREADS * NUM_REQUESTS * len(QUERIES)

    print(f"Total Queries: {total_queries}")
    print(f"Queries per second: {total_queries / total_time:.2f} QPS")
    print(f"Total Execution Time: {total_time:.2f} sec")


if __name__ == "__main__":
    stress_test()

