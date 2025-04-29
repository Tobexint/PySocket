# Documentation

## File Structure
- The .env file stores the environment variable for the config.ini file.
- The data folder holds the'k.txt' files which contains the sample search strings.
- The requirements.txt file contains the project dependencies.
- The server.py file contains the server code.
- The client.py is the client for testing the server.
- The speed_test.py file compares the various search algorithms.
- The stress_server_test.py file simulates the server performance under high load.
- The log folder contains the log output.
- The ssl folder holds the ssl.crt and cert.key files that contains the ssl certificate and key respectively.
- The config.ini is the configuration file.
- The docs folder contains the project documentation.
- The tests folder contains the test files.

## Overview
This server listens for incoming client connections and searches for user-provided strings in a preloaded file. It supports:
- Multithreading for handling multiple clients simultaneously.
- Configurable SSL for secure connections.
- Dynamic file reloading based on configuration.
- Efficient lookup using a hash set.

## Configuration
The server(server.py) reads its settings from a configuration file (`config.ini`).

### Configuration Parameters
| Parameter          | Description                                                   | Type    | Default |
|-------------------|---------------------------------------------------------------|---------|---------|
| linuxpath        | Path to the file containing searchable strings                | String  | None    |
| REREAD_ON_QUERY  | Whether to reload the file on every query                     | Boolean | False   |
| USE_SSL          | Whether to enable SSL encryption                              | Boolean | False   |
| CERTFILE         | Path to the SSL certificate file                              | String  | None    |
| KEYFILE          | Path to the SSL private key file                              | String  | None    |
| PSK             | Pre-shared key for SSL encryption (not implemented)           | String  | None    |
| PORT            | Port number on which the server listens                        | Integer | 12345   |

## Components and Functions

### 1. Configuration Loader (`load_config`)
**Function:** Loads server configuration from `config.ini`.
- Uses Python’s ConfigParser to read configuration values from a .ini file.
- Dynamically resolves the full absolute path to the config.ini file, based on the location of the script.
- Reads values for file path, SSL settings, port, etc.
- Validates SSL configuration if enabled.
- Returns the configuration parameters.

### 2. File Loader (`load_file_into_set`)
**Function:** Loads a file into a set for quick lookups.
- Strips whitespace and stores each line as a set entry.
- Raises errors if the file is missing or unreadable.

### 3. String Search (`search_string_in_set`)
**Function:** Checks if a string exists in the preloaded hash set.
- Uses set membership for fast lookups (`O(1)` complexity).

### 4. Client Handler (`handle_client`)
**Function:** Processes client queries.
- Receives and decodes the client's query.
- Prevents oversized queries (limit: 200 characters).
- Searches for the string in the preloaded file data.
- Sends a response (`STRING EXISTS` or `STRING NOT FOUND`).
- Handles errors gracefully (socket errors, decoding issues, etc.).

### 5. Server Startup (`start_server`)
**Function:** Initializes and runs the server.
- Loads data into memory if `REREAD_ON_QUERY` is disabled.
- Creates and binds a socket to the specified port.
- Supports SSL encryption if configured.
- Listens for incoming connections and starts threads for each client.
- Gracefully handles shutdown on keyboard interruption.

## Usage
### Running the Server
To start the server, ensure `config.ini` is properly configured and run:
```bash
python server.py
```

### Client Interaction
- The client sends a query (a single string).
- The server responds with `STRING EXISTS` if found, otherwise `STRING NOT FOUND`.

### Example Client Request
Execute on a different terminal window.
```bash
python client.py
```

## Error Handling
| Error Message                    | Cause                                       | Resolution                        |
|-----------------------------------|--------------------------------------------|----------------------------------|
| `File not found: <path>`         | Configured file does not exist             | Check `linuxpath` in `config.ini`|
| `ERROR: Query too long`          | Query exceeds 200 characters               | Send a shorter query            |
| `ERROR: Unable to read data file`| File is missing or unreadable              | Verify file path and permissions|
| `ERROR: Server encountered an error` | Unexpected issue in query processing  | Check server logs                |

## Security Considerations
To enable ssl, set it to true in both the client.py and config.ini files.
- SSL encryption can be enabled for secure communication: Once you set it to True in the config.ini file, be sure to also set it to True in the client code.
- Large queries are blocked to prevent abuse.
- Errors are handled gracefully to prevent crashes.

# Server Stress Test Script Documentation

## Overview
This script is designed to stress test a server by simulating multiple concurrent clients sending queries. It measures the server's response time and calculates the queries per second (QPS) to evaluate performance under heavy load. This script was tested on a 250,000 lines file.

## Requirements
- Python 3.x
- A running server that listens on the specified `HOST` and `PORT`
- Basic knowledge of networking and socket programming

## Configuration
The following parameters can be adjusted to customize the test:
- `HOST`: IP address of the server (default: `127.0.0.1`)
- `PORT`: Port number where the server is listening (default: `12345`)
- `NUM_THREADS`: Number of concurrent client threads (default: `100`)
- `NUM_REQUESTS`: Number of queries each thread sends per query type (default: `1000`)
- `QUERIES`: A list of test query strings sent to the server

## Functions
### `send_query(query)`
- Sends a single query to the server.
- Measures the response time.
- Prints the query, response, and latency.
- Handles connection errors.

### `stress_test()`
- Spawns multiple threads to simulate high query load.
- Each thread sends multiple queries from `QUERIES` list.
- Measures the total execution time and calculates QPS.
- Prints performance metrics.

## Execution
Run the script using:
```bash
python stress_server_test.py
```

## Output
The script prints:
- Query, response, and latency per request.
- Total number of queries sent.
- Queries per second (QPS).
- Total execution time.

## Example Output
```
Query: 'test_line_1' | Response: 'Success' | Latency: 0.003210 sec
Query: 'nonexistent' | Response: 'Not Found' | Latency: 0.004512 sec
...
Total Queries: 700000
Queries per second: 1523.45 QPS
Total Execution Time: 459.87 sec
```

## Notes
- Ensure the server is running before executing the script.
- Modify `HOST` and `PORT` as needed.
- High `NUM_THREADS` and `NUM_REQUESTS` values may overwhelm the server.

## Troubleshooting
- **Connection refused**: Ensure the server is running and listening on the specified `HOST` and `PORT`.
- **Slow response times**: Check network latency and server performance.
- **Script crashes**: Reduce `NUM_THREADS` or `NUM_REQUESTS` to lower the load.

## License
This script is provided under the MIT License. Modify and use it at your own discretion.

## Linux Daemon Installation Instructions
1. Prerequisites
- A Linux based system
- Python installed
- Root or sudo access

2. Prepare Your Python Scripts
Ensure your script is in a known directory then modify your script to run continuously and handle termination signals.
Make the script executable.

3.Create a Systemd Service File
Add the following content:
[Unit]
Description=My Python Daemon Service
After=network.target

[Service]
ExecStart=/usr/bin/python3 /home/user/ALGO/myscript.py
WorkingDirectory=/home/user/ALGO
Restart=always
User=user
StandardOutput=append:/home/user/ALGO/myscript_output.log
StandardError=append:/home/user/ALGO/myscript_error.log

[Install]
WantedBy=multi-user.target

Save and exit

4. Reload Systemd and Enable the Service
Run the following commands:
sudo systemctl daemon-reload
sudo systemctl enable mypythonservice
sudo systemctl start mypythonservice

5. Manage the Service
Check service status:  sudo systemctl status mypythonservice
Restart service:  sudo systemctl restart mypythonservice
Stop service:  sudo systemctl stop mypythonservice

6. Remove The Service
sudo systemctl stop mypythonservice
sudo systemctl disable mypythonservice
sudo rm /etc/systemd/system/mypythonservice.service
sudo systemctl daemon-reload
