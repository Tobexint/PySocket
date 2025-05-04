## File Structure
- The .env file stores the environment variable for the config.ini file.
- The data folder holds the 'k.txt' files that contains the sample search strings.
- The requirements.txt file contains the project dependencies.
- The server.py file contains the server code.
- The client.py is the client for testing the server.
- The speed_test.py file compares the various search algorithms.
- The stress_server_test.py file simulates the server performance under high load.
- The log folder contains the log output.
- The ssl folder houses the ssl.crt and cert.key files that contains the ssl certificate and key respectively.
- The config.ini is the configuration file.
- The docs folder contains the project's documentation(check the documentation.md file ).
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
Generate SSL files (self-signed certificate)

1. Generate a 2048-bit RSA private key:
On your terminal, run: openssl genrsa -out cert.key 2048

2. Create a certificate signing request (CSR):
   - openssl req -new -key cert.key -out server.csr

3. Generate a self-signed certificate valid for one year:
   - openssl x509 -req -days 365 -in server.csr -signkey cert.key -out ssl.crt


## Running a Python Script as a Windows Service Using NSSM
1. Prerequisites
Windows OS

Python installed (Check with 'which python' in Git Bash)

NSSM (Non-Sucking Service Manager)

2. Install NSSM
Download from https://nssm.cc/download.

Extract and move nssm.exe to C:\Windows\System32\ for easy access.

3. Prepare Your Python Script
Ensure your script (server.py) is located in a known directory (e.g., C:\Users\USER\ALGO\).

4. Install the Service with NSSM
Run:

```bash
nssm install MyPythonService
```
In the GUI:

Path: Set to Python executable (e.g., C:\Python312\python.exe).

Startup directory: C:\Users\USER\ALGO.

Arguments: server.py.

I/O Tab:

Stdout: C:\Users\USER\ALGO\server_output.log.

Stderr: C:\Users\USER\ALGO\server_error.log.

Click Install Service.

5. Start and Manage the Service
Start service:

```bash
nssm start MyPythonService
```
Check status:

```bash
nssm status MyPythonService
```
Restart:

```bash
nssm restart MyPythonService
```
Stop:

```bash
nssm stop MyPythonService
```
Remove:

```bash
nssm remove MyPythonService confirm
```

Running The Test Files
1. Client File test
```bash
pytest test_client.py
```

2. Server File Test
```bash
pytest test_server.py
```
3. Speed Test
Toggle reread_on_query options to true/false then run:
```bash
python speed_test.py
```

4. Stress Test
```bash
python stress_server_test.py
```
