## File Structure
- The .env file stores the environment variable for the config.ini file.

- The data folder holds the k.txt files that contain the sample search strings.

- The requirements.txt file contains the project dependencies.

- The server.py file contains the server code.

- client.py is the client for testing the server.

- The speed_test.py file compares the various search algorithms.

- The stress_server_test.py file simulates the server's performance under high load.

- The log folder contains the log output.

- The ssl folder holds the ssl.crt and cert.key files that contain the ssl certificate and key respectively.

- The config.ini file is the configuration file.

- The docs folder contains the project's documentation (see documentation.md).

- The tests folder contains the pytest files.

## Installation
To install dependencies, run: pip install -r requirements.txt

## Load the env file
echo CONFIG=config.ini > .env

## Unit Testing
In the root folder, run:
- 'pytest tests/test_server.py' to test the server.
- 'pytest tests/test_client.py' to test the client.

Alternatively in the tests folder, run:
- python -m pytest test_server.py
- python -m pytest test_client.py


## Setting Up SSL for Secure Communication
To enable HTTPS and secure communication between the client and server, you need to generate an SSL certificate and key files.
For development purposes, you can create a self-signed certificate using the steps below:

1. Generate a 2048-bit RSA private key:
On your terminal, run: openssl genrsa -out cert.key 2048

2. Create a certificate signing request (CSR):
   - openssl req -new -key cert.key -out server.csr

3. Generate a self-signed certificate valid for one year:
   - openssl x509 -req -days 365 -in server.csr -signkey cert.key -out ssl.crt

This will produce:
    - cert.key : Your private key
    - ssl.crt : Your SSL certificate

## Linux Daemon Installation Instructions
1. Prerequisites
    - Linux Operating System
    - Python installed
    - Your script (e.g., server.py) in a known directory

2. Create a systemd service file.
```bash
sudo vim /etc/systemd/system/mypythonservice.service
```
Paste the following:
"""
[Unit]
Description=My Python Service
After=network.target

[Service]
Type=simple
User=youruser
WorkingDirectory=/home/youruser/ALGO
ExecStart=/usr/bin/python3 /home/youruser/ALGO/server.py
StandardOutput=append:/home/youruser/ALGO/server_output.log
StandardError=append:/home/youruser/ALGO/server_error.log
Restart=always

[Install]
WantedBy=multi-user.target
"""
Note: Replace 'youruser' and paths with actual values.

3. Enable and start the service.
```bash
sudo systemctl daemon-reexec
sudo systemctl daemon-reload
sudo systemctl enable mypythonservice.service
sudo systemctl start mypythonservice.service
```
4. Manage the service.
```bash
sudo systemctl status mypythonservice.service
sudo systemctl restart mypythonservice.service
sudo systemctl stop mypythonservice.service
sudo systemctl disable mypythonservice.service
```

## Running as a Linux Daemon
To run the server in the background as a daemon process(detached from the terminal):
```bash
python server.py --daemon
```
- **Output Redirection:** When run as a daemon, sys.stdout and sys.stderr are flushed, but by default, they are not redirected to a file. For production use, it's highly recommended to redirect standard output and standard error to log files.
```bash
python server.py --daemon > /var/log/server.log 2>&1 &
```
This command will:
- > /var/log/server.log: Redirect standard output to server.log.
- 2>&1: Redirect standard error to the same location as standard output.
- &: Run the command in the background.

Note: Replace the file paths with the appropriate values.

- **Checking Daemon Status:** You can use ps and grep to check if the daemon is running:
```bash
ps aux | grep server.py
```

- **Stopping the Daemon:** You'll need to find the process ID (PID) using ps aux and then use kill to terminate it:
```bash
kill <PID>
```
For example: kill 12345 (replace 12345 with the actual PID).

## Running the Test Files
1. Client File test
```bash
pytest test_client.py
```

2. Server File Test
```bash
pytest test_server.py
```
3. Speed Test
Toggle reread_on_query options to true or false then run:
```bash
python speed_test.py
```

4. Stress Test
```bash
python stress_server_test.py
```
