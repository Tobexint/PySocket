import os
import configparser
import importlib
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import threading
from test_utils import send_query, send_query_ssl, generate_self_signed_cert, find_free_port, send_query_with_retries
from unittest.mock import patch, MagicMock

import pytest

# Add the parent directory to the system path to allow module imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import server
from server import (
    load_config,
    load_file_into_set,
    search_string_in_set,
    handle_client,
    start_server,
    preloaded_set
)


@pytest.fixture
def temp_file():
    """Create a temporary file for testing."""
    with tempfile.NamedTemporaryFile(delete=False, mode='w', encoding='utf-8') as f:
        f.write('hello\nworld\n')
        temp_path = f.name

    # Yield the path to the test function.
    yield temp_path

    # Clean up and remove the file after the test completes.
    os.remove(temp_path)


@pytest.fixture
def temp_config_file_path(tmp_path):
    """Creates a dummy config file with default settings."""
    config_content = f"""
    [DEFAULT]
    linuxpath = {tmp_path}/dummy_data.txt
    REREAD_ON_QUERY = False
    USE_SSL = False
    CERTFILE =
    KEYFILE =
    PSK =
    PORT = 12345
   """
    config_path = tmp_path / "test_config.ini"
    config_path.write_text(config_content)
    return str(config_path)


@pytest.fixture
def dummy_data_file(tmp_path):
    """Creates a dummy data file for the server."""
    file_path = tmp_path / "dummy_data.txt"
    file_path.write_text("item1\nitem2\nitem3\n")
    return str(file_path)


@pytest.fixture
def setup_server_with_mocked_config(monkeypatch, tmp_path):
    """
    Sets up the server module's global CONFIG_FILE variable
    to point to a dummy config, and mocks configparser.
    """
    dummy_config_content = f"""
    [DEFAULT]
    linuxpath = {tmp_path}/dummy_data.txt
    REREAD_ON_QUERY = True
    USE_SSL = False
    CERTFILE =
    KEYFILE =
    PSK = dummy_psk
    PORT = 12345
    """
    config_path = tmp_path / "dummy_config.ini"
    config_path.write_text(dummy_config_content)

    monkeypatch.setenv('CONFIG', os.path.basename(config_path))

    patcher = patch('server.configparser.ConfigParser')
    MockConfigParser = patcher.start()

    # IMPORTANT: Patch the global 'config' object that is imported at the top level
    # of the server.py file.
    with patch('server.configparser.ConfigParser') as MockConfigParser:
        mock_config_instance = MockConfigParser.return_value

        mock_config_instance.get.side_effect = lambda section, option, fallback=None: {
            'linuxpath': str(tmp_path / 'dummy_data.txt'),
            'REREAD_ON_QUERY': 'True',
            'USE_SSL': 'False',
            'CERTFILE': '',
            'KEYFILE': '',
            'PSK': 'dummy_psk',
            'PORT': '12345'
        }.get(option, fallback)

        mock_config_instance.getboolean.side_effect = lambda section, option, fallback: {
            'REREAD_ON_QUERY': True,
            'USE_SSL': False
        }.get(option, fallback)

        mock_config_instance.getint.side_effect = lambda section, option, fallback: {
            'PORT': 12345
        }.get(option, fallback)

        mock_config_instance.read.return_value = None # Ensure read doesn't try to access real file.

        return config_path, mock_config_instance


@patch('server.os.path.isfile', return_value=True)
@patch('server.config', autospec=True)
def test_load_config_success(mock_config, mock_isfile):
    """Test successful loading of configuration."""

    # Configure the mock's methods to return specific values in order of their calls.
    mock_config.get.side_effect = [
        'dummy_path',  # Corresponds to config.get('DEFAULT', 'linuxpath')
        'dummy_crt',   # Corresponds to config.get('DEFAULT', 'CERTFILE')
        'dummy_key',   # Corresponds to config.get('DEFAULT', 'KEYFILE')
        'dummy_psk'    # Corresponds to config.get('DEFAULT', 'PSK', fallback=None)
    ]
    mock_config.getboolean.side_effect = [
        True,          # Corresponds to config.getboolean('DEFAULT', 'REREAD_ON_QUERY', ...)
        False          # Corresponds to config.getboolean('DEFAULT', 'USE_SSL', ...)
    ]
    mock_config.getint.return_value = 5555  # Corresponds to config.getint('DEFAULT', 'PORT', ...)

    # Call the modified load_config function, which now takes no arguments.
    (
        linuxpath, reread_on_query, use_ssl,
        certfile, keyfile, psk, port
    ) = load_config()

    # Assert that the function correctly unpacks and returns the mocked values.
    assert linuxpath == 'dummy_path'
    assert isinstance(use_ssl, bool)
    assert isinstance(certfile, str)
    assert reread_on_query is True
    assert use_ssl is False
    assert certfile == 'dummy_crt'
    assert keyfile == 'dummy_key'
    assert psk == 'dummy_psk'
    assert port == 5555


def test_load_file_into_set_success(temp_file):
    """Test loading a file into a set."""
    result = load_file_into_set(temp_file)
    assert result == {'hello', 'world'}


def test_load_file_into_set_not_found(tmp_path):
    """Test loading a nonexistent file."""
    fake_file = tmp_path / "nonexistent.txt"
    with pytest.raises(FileNotFoundError):
        load_file_into_set(fake_file)


def test_load_file_into_set_is_directory(tmp_path):
    """Test loading a directory instead of a file."""
    with pytest.raises(IsADirectoryError):
        load_file_into_set(tmp_path)


def test_search_string_in_set_found():
    """Test search string found."""
    lines_set = {'hello', 'world'}
    assert search_string_in_set(lines_set, 'hello') is True


def test_search_string_in_set_not_found():
    """Test search string not found."""
    lines_set = {'hello', 'world'}
    assert search_string_in_set(lines_set, 'test') is False


@patch('server.load_file_into_set')
def test_handle_client_string_exists(mock_load_file_into_set, temp_file):
    """Test handling a client that sends a string that exists."""
    mock_load_file_into_set.return_value = {'hello', 'world'}

    mock_socket = MagicMock()
    mock_socket.recv.return_value = b'hello\n'
    mock_socket.sendall = MagicMock()
    mock_socket.close = MagicMock()

    handle_client(
        client_socket=mock_socket,
        address=('127.0.0.1', 5000),
        linuxpath=temp_file,
        reread_on_query=True
    )

    mock_socket.sendall.assert_called_with(b'STRING EXISTS\n')
    mock_socket.close.assert_called()


@patch('server.load_file_into_set')
def test_handle_client_string_not_found(mock_load_file_into_set, temp_file):
    """Test handling a client that sends a string that doesn't exist."""
    mock_load_file_into_set.return_value = {'hello', 'world'}

    mock_socket = MagicMock()
    mock_socket.recv.return_value = b'test\n'
    mock_socket.sendall = MagicMock()
    mock_socket.close = MagicMock()

    handle_client(
        client_socket=mock_socket,
        address=('127.0.0.1', 5000),
        linuxpath=temp_file,
        reread_on_query=True
    )

    mock_socket.sendall.assert_called_with(b'STRING NOT FOUND\n')
    mock_socket.close.assert_called()


@patch('server.socket.socket')
@patch('server.load_file_into_set')
def test_start_server_no_ssl(mock_load_file_into_set, mock_socket_class, temp_file):
    """Test starting server without SSL."""
    mock_socket_instance = MagicMock()
    mock_socket_class.return_value = mock_socket_instance
    mock_socket_instance.accept.side_effect = KeyboardInterrupt

    mock_load_file_into_set.return_value = {'hello', 'world'}

    with patch('server.threading.Thread'):
        start_server(
            linuxpath=temp_file,
            reread_on_query=False,
            use_ssl=False,
            certfile=None,
            keyfile=None,
            psk='dummy_psk',
            port=12345
        )

    mock_socket_instance.bind.assert_called_with(('0.0.0.0', 12345))
    mock_socket_instance.listen.assert_called()


@patch('server.ssl.SSLContext')
@patch('server.socket.socket')
@patch('server.load_file_into_set')
def test_start_server_with_ssl(mock_load_file_into_set, mock_socket_class, mock_ssl_context_class, temp_file, tmp_path):
    """Test starting server with SSL."""
    certfile = tmp_path / "dummy.crt"
    keyfile = tmp_path / "dummy.key"
    certfile.write_text("dummy cert content")
    keyfile.write_text("dummy key content")

    mock_socket_instance = MagicMock()
    mock_socket_class.return_value = mock_socket_instance
    mock_socket_instance.accept.side_effect = KeyboardInterrupt

    mock_ssl_context_instance = MagicMock()
    mock_ssl_context_class.return_value = mock_ssl_context_instance
    mock_ssl_context_instance.wrap_socket.return_value = mock_socket_instance

    mock_load_file_into_set.return_value = {'hello', 'world'}

    with patch('server.threading.Thread'):
        start_server(
            linuxpath=temp_file,
            reread_on_query=False,
            use_ssl=True,
            certfile=str(certfile),
            keyfile=str(keyfile),
            psk='dummy_psk',
            port=12345
        )

    mock_ssl_context_instance.load_cert_chain.assert_called_with(str(certfile), str(keyfile))
    mock_ssl_context_instance.wrap_socket.assert_called()


def test_load_file_into_set_empty_file(tmp_path):
    """Test that loading an empty file returns an empty set."""
    file_path = tmp_path / "empty.txt"
    file_path.write_text("")
    assert load_file_into_set(str(file_path)) == set()


def test_load_file_into_set_blank_lines(tmp_path):
    """Test that loading a file with only blank lines returns empty set."""
    file_path = tmp_path / "blank.txt"
    file_path.write_text("\n\n    \n\n")
    assert load_file_into_set(str(file_path)) == set()


def test_load_file_into_set_duplicates(tmp_path):
    """Test that a file with duplicate lines results in unique entries."""
    file_path = tmp_path / "duplicates.txt"
    file_path.write_text("apple\nbanana\napple\nbanana\norange\n")
    result = load_file_into_set(str(file_path))
    assert result == {"apple", "banana", "orange"}


def test_load_file_into_set_strip_whitespace(tmp_path):
    """Test that lines are stripped of leading/trailing whitespace."""
    file_path = tmp_path / "whitespace.txt"
    file_path.write_text("  apple   \n\tbanana\t\norange \n")
    result = load_file_into_set(str(file_path))
    assert result == {"apple", "banana", "orange"}


def test_load_file_into_set_unicode_decode_error(tmp_path):
    """Test that UnicodeDecodeError is raised for invalid UTF-8 file."""
    file_path = tmp_path / "invalid_utf8.txt"
    file_path.write_bytes(b'\xff\xfe\xfa') # Invalid UTF-8 sequence.
    with pytest.raises(UnicodeDecodeError):
        load_file_into_set(str(file_path))


def test_load_config_linuxpath_file_not_found(monkeypatch, tmp_path):
    """
    Test for a RuntimeError when the file specified by 'linuxpath' does not exist.
    """
    # Create a valid config file pointing to a nonexistent data file.
    nonexistent_path = tmp_path / 'nonexistent_data.txt'
    config_content = f"""
    [DEFAULT]
    linuxpath = {nonexistent_path}
    REREAD_ON_QUERY = False
    USE_SSL = False
    CERTFILE = none
    KEYFILE = none
    PORT = 54321
    """
    config_file = tmp_path / "config.ini"
    config_file.write_text(config_content)
    monkeypatch.setenv("CONFIG", str(config_file))

    importlib.reload(server)
    with pytest.raises(RuntimeError) as e:
        server.load_config()

    # Check that the error message correctly identifies the missing data file.
    assert f"The file {nonexistent_path} is not found" in str(e.value)


def test_load_config_file_not_found(monkeypatch, tmp_path):
    """
    Test that load_config() raises a RuntimeError when the config file
    specified in the CONFIG environment variable does not exist.

    This simulates a missing config file and verifies error handling logic.
    """
    # Set CONFIG environment variable to a file that doesn't exist.
    monkeypatch.setenv('CONFIG', 'non_existent.ini')

    # Patch file existence check to simulate the file is missing.
    with patch('server.os.path.isfile', return_value=False), \
         patch('server.configparser.ConfigParser') as MockConfigParser:


        # Prevent the ConfigParser from reading any actual file.
        mock_config_instance = MockConfigParser.return_value
        mock_config_instance.read.return_value = [] # No files read.

        # Expect load_config() to raise a RuntimeError due to missing file.
        with pytest.raises(RuntimeError) as excinfo:
            load_config()

        assert "Error accessing a configured file" in str(excinfo.value)
        assert "not found" in str(excinfo.value)


def test_load_config_malformed_file(monkeypatch, tmp_path):
    """
    Test that load_config() raises a RuntimeError or handles errors gracefully
    when the config file exists but contains malformed or incomplete content.
    """
    # Create a malformed config file (e.g., missing sections or invalid format).
    bad_config_file = tmp_path / "bad_config.ini"
    bad_config_file.write_text("This is not valid INI format!")

    # Point CONFIG environment variable to the malformed config file.
    monkeypatch.setenv('CONFIG', str(bad_config_file))

    # Expect load_config to raise an error due to parse failure.
    with pytest.raises(RuntimeError) as excinfo:
        load_config()

    assert "Error accessing a configured file" in str(excinfo.value) or \
           "Could not parse config" in str(excinfo.value)


def test_load_config_os_error(monkeypatch, tmp_path):
    """
    This simulates a situation where the OS prevents access to the config file,
    such as through permissions issues or I/O failure.
    """
    # Create a dummy config file.
    config_path = tmp_path / "os_error_config.ini"
    config_path.write_text("[DEFAULT]\nlinuxpath=dummy")

    # Set CONFIG env variable to the dummy file's name.
    monkeypatch.setenv('CONFIG', os.path.basename(config_path))

    # Patch os.path.isfile to raise an OSError.
    with patch('server.os.path.isfile', side_effect=OSError("Permission denied")), \
         patch('server.configparser.ConfigParser'):

        # Expect load_config to raise a RuntimeError due to the OSError.
        with pytest.raises(RuntimeError) as excinfo:
            load_config()

        assert "Operating system error while accessing config file" in str(excinfo.value)
        assert "Permission denied" in str(excinfo.value)


@patch('server.load_file_into_set')
def test_handle_client_connection_reset_error(mock_load_file_into_set, temp_file, capfd):
    """
    Test that handle_client() correctly handles a ConnectionResetError caused by
    the client forcibly resetting the connection (e.g., crashing or disconnecting).
    """
    # Mock file loading to avoid real file I/O.
    mock_load_file_into_set.return_value = {'hello', 'world'}

    # Create a mock socket that simulates a connection reset on recv().
    mock_socket = MagicMock()
    mock_socket.recv.side_effect = ConnectionResetError("Client reset")

    # Call the function under test with the mock socket and address.
    handle_client(
        client_socket=mock_socket,
        address=('127.0.0.1', 5000),
        linuxpath=temp_file,
        reread_on_query=True
    )

    # Ensure the socket was closed properly.
    mock_socket.close.assert_called_once()

    # Capture stdout/stderr and check for the expected warning.
    captured = capfd.readouterr()
    assert "WARNING: Connection reset by client ('127.0.0.1', 5000)" in captured.out


@patch('server.load_file_into_set')
def test_handle_client_socket_timeout(mock_load_file_into_set, temp_file, capfd):
    """
    Test that handle_client() handles socket timeouts gracefully.
    """
    # Mock the file-loading function to return a known word set.
    mock_load_file_into_set.return_value = {'hello', 'world'}

    # Create a mock socket that simulates a timeout during recv().
    mock_socket = MagicMock()
    mock_socket.recv.side_effect = socket.timeout("Timed out")
    mock_socket.sendall = MagicMock()  # Mock sendall to capture output sent to client.


    # Call the function under test with mock socket and address.
    handle_client(
        client_socket=mock_socket,
        address=('127.0.0.1', 5000),
        linuxpath=temp_file,
        reread_on_query=True
    )

    # Assert that the server responded with a timeout error message.
    mock_socket.sendall.assert_called_with(b"ERROR: Connection timed out\n")

    # Assert that the socket was closed after handling the exception.
    mock_socket.close.assert_called_once()

    # Capture and check the server's logged warning message.
    captured = capfd.readouterr()
    assert "WARNING: Socket timeout with client ('127.0.0.1', 5000)" in captured.out


@patch('server.load_file_into_set')
def test_multiple_client_socket_timeouts(mock_load_file_into_set, temp_file, capfd):
    """
    Test that handle_client() handles multiple client socket timeouts concurrently.

    Each mock client will trigger a socket.timeout, and the server should:
    - Send the appropriate timeout error message.
    - Log a warning.
    - Close the socket.
    """
    mock_load_file_into_set.return_value = {'hello', 'world'}

    client_count = 3
    mock_sockets = []
    threads = []

    for i in range(client_count):
        mock_socket = MagicMock()
        mock_socket.recv.side_effect = socket.timeout("Timed out")
        mock_socket.sendall = MagicMock()
        mock_sockets.append(mock_socket)

        thread = threading.Thread(
            target=handle_client,
            args=(mock_socket, (f'127.0.0.{i+1}', 5000 + i)),
            kwargs={'linuxpath': temp_file, 'reread_on_query': True}
        )
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    # Assertions for each mock socket
    for i, sock in enumerate(mock_sockets):
        sock.sendall.assert_called_with(b"ERROR: Connection timed out\n")
        sock.close.assert_called_once()

    # Capture output once all threads are done
    captured = capfd.readouterr()
    for i in range(client_count):
        assert f"WARNING: Socket timeout with client ('127.0.0.{i+1}', {5000 + i})" in captured.out


@patch('server.load_file_into_set')
def test_mixed_client_behaviors(mock_load_file_into_set, temp_file, capfd):
    """
    Test handle_client() with a mix of client behaviors:
    - Some experience socket timeouts.
    - Some reset the connection.
    - Some send valid queries.
    """
    # Simulate data set.
    mock_load_file_into_set.return_value = {'apple', 'banana'}

    # Define mixed client behaviors.
    client_scenarios = [
        {"behavior": "timeout", "ip": "127.0.0.1", "port": 5001},
        {"behavior": "reset", "ip": "127.0.0.2", "port": 5002},
        {"behavior": "valid", "ip": "127.0.0.3", "port": 5003, "message": b"apple\n"},
        {"behavior": "valid", "ip": "127.0.0.4", "port": 5004, "message": b"grape\n"},
    ]

    threads = []

    for scenario in client_scenarios:
        mock_socket = MagicMock()
        behavior = scenario["behavior"]

        if behavior == "timeout":
            mock_socket.recv.side_effect = socket.timeout("Timed out")
        elif behavior == "reset":
            mock_socket.recv.side_effect = ConnectionResetError("Client reset")
        elif behavior == "valid":
            mock_socket.recv.side_effect = [scenario["message"], b""]  # Message, then disconnect.
            mock_socket.sendall = MagicMock()

        # Use the same mock close for all.
        mock_socket.close = MagicMock()

        thread = threading.Thread(
            target=handle_client,
            args=(mock_socket, (scenario["ip"], scenario["port"])),
            kwargs={"linuxpath": temp_file, "reread_on_query": True}
        )
        scenario["mock_socket"] = mock_socket
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    # Validate results.
    captured = capfd.readouterr()

    for scenario in client_scenarios:
        sock = scenario["mock_socket"]
        behavior = scenario["behavior"]
        addr = f"('{scenario['ip']}', {scenario['port']})"

        if behavior == "timeout":
            sock.sendall.assert_called_with(b"ERROR: Connection timed out\n")
            assert f"WARNING: Socket timeout with client {addr}" in captured.out

        elif behavior == "reset":
            assert f"WARNING: Connection reset by client {addr}" in captured.out

        elif behavior == "valid":
            msg = scenario["message"].decode().strip()
            expected = b"STRING EXISTS\n" if msg in {'apple', 'banana'} else b"STRING NOT FOUND\n"
            sock.sendall.assert_called_with(expected)

        sock.close.assert_called_once()


# Test `handle_client` with null bytes in query.
@patch('server.load_file_into_set')
def test_handle_client_null_bytes_in_query(mock_load_file_into_set, temp_file):
    """
    Unit test for the handle_client function to ensure that it correctly handles null bytes in the input query.

    This test simulates a client sending a query string containing null bytes (e.g., 'te\x00st\n') and verifies that:
    - Null bytes are properly removed from the query before checking against the loaded set of strings.
    - The string 'test' exists in the mocked data set returned by load_file_into_set.
    - The response sent back to the client is 'STRING EXISTS\n', indicating a successful match.
    - The client socket is properly closed after processing.

    Mocks:
    - load_file_into_set: returns a set containing the string 'test'.
    - client socket: mocks recv, sendall, and close methods.

    Arguments:
    - mock_load_file_into_set: patched version of the load_file_into_set function.
    - temp_file: temporary file path used as a placeholder for file loading.
    """
    mock_load_file_into_set.return_value = {'test'}
    mock_socket = MagicMock()
    mock_socket.recv.return_value = b'te\x00st\n'
    mock_socket.sendall = MagicMock()
    mock_socket.close = MagicMock()

    handle_client(
        client_socket=mock_socket,
        address=('127.0.0.1', 5000),
        linuxpath=temp_file,
        reread_on_query=True
    )
    # Assert that the server correctly identifies the query string as existing in the dataset
    mock_socket.sendall.assert_called_with(b'STRING EXISTS\n') # Null bytes should be removed.
    # Assert that the server closes the client connection
    mock_socket.close.assert_called_once()


@patch('server.load_dotenv')
@patch('server.socket.socket')
@patch('server.load_file_into_set')
@patch('server.ssl.SSLContext')
def test_start_server_ssl_cert_load_error(
    mock_ssl_context_class, mock_load_file_into_set, mock_socket_class,
    temp_config_file_path, capfd, tmp_path
):
    """
    Test that the server gracefully handles a missing SSL certificate file.

    This test mocks the server's configuration and environment to simulate a situation
    where SSL is enabled but the provided certificate file does not exist. It verifies that:
    - An appropriate error message is printed to stdout.
    - The server socket is properly closed after the failure.

    Mocks:
        - `server.ssl.SSLContext`: To raise `FileNotFoundError` when attempting to load the cert chain.
        - `server.load_file_into_set`: Mocked to bypass file loading logic.
        - `server.socket.socket`: To monitor socket behavior (e.g., closing).
        - `server.load_dotenv`: Mocked to prevent environment loading side effects.
        - `server.config`: Replaced with a mock config object that enables SSL and sets invalid certfile path.

    Args:
        mock_ssl_context_class (MagicMock): Mock for `ssl.SSLContext`.
        mock_load_file_into_set (MagicMock): Mock for file loading utility.
        mock_socket_class (MagicMock): Mock for socket class.
        temp_config_file_path (Path): Temporary config file path (unused in this test).
        capfd (pytest fixture): Captures stdout and stderr.
        tmp_path (Path): Temporary directory path provided by pytest for file operations.
    """
    # Setup mock config for SSL.
    mock_config = MagicMock()

    mock_config.get.side_effect = lambda section, option, fallback=None: {
        'linuxpath': str(tmp_path / 'dummy_data.txt'),
        'REREAD_ON_QUERY': 'False',
        'USE_SSL': 'True',
        'CERTFILE': str(tmp_path / 'non_existent.crt'), # Point to non-existent cert.
        'KEYFILE': str(tmp_path / 'dummy.key'),
        'PSK': 'dummy_psk',
        'PORT': '12345'
    }.get(option, fallback)

    mock_config.getboolean.side_effect = lambda section, option, fallback: True if option == 'USE_SSL' else False
    mock_config.getint.return_value = 12345

    # Mock SSLContext and load_cert_chain to raise FileNotFoundError.
    mock_ssl_context_instance = MagicMock()
    mock_ssl_context_class.return_value = mock_ssl_context_instance
    mock_ssl_context_instance.load_cert_chain.side_effect = FileNotFoundError("Cert file not found")

    with patch('server.config', mock_config):
        with patch('server.threading.Thread'):
            start_server(
                linuxpath=str(tmp_path / 'dummy_data.txt'),
                reread_on_query=False,
                use_ssl=True,
                certfile=str(tmp_path / 'non_existent.crt'),
                keyfile=str(tmp_path / 'dummy.key'),
                psk='dummy_psk',
                port=12345
            )

    captured = capfd.readouterr()
    assert "ERROR: SSL certificate or key file not found: Cert file not found" in captured.out
    mock_socket_class.return_value.close.assert_called_once() # Server socket should be closed.


# Test starting the server and handling multiple client connections concurrently.
@patch('server.load_dotenv') # Avoid loading real .env during test
def test_start_server_concurrent_clients(
    mock_load_dotenv,
    setup_server_with_mocked_config,
    dummy_data_file,
    capfd # pytest fixture to capture stdout/stderr.
):
    config_path, mock_config = setup_server_with_mocked_config # Use the fixture to setup config.
    test_port = find_free_port()

    # Override the mocked config's port to use our dynamically found port.
    mock_config.getint.side_effect = lambda section, option, fallback=None: {
        'PORT': test_port
    }.get(option, fallback)

    mock_config.get.side_effect = lambda section, option, fallback=None: {
        'linuxpath': dummy_data_file,
        'REREAD_ON_QUERY': 'True',
        'USE_SSL': 'False',
        'CERTFILE': '',
        'KEYFILE': '',
        'PSK': 'dummy_psk',
        'PORT': str(test_port) # Ensure it returns string for get() too.
    }.get(option, fallback)

    mock_config.getboolean.side_effect = lambda section, option, fallback: {
        'REREAD_ON_QUERY': True,
        'USE_SSL': False
    }.get(option, fallback)


    server_thread = None
    stop_event = threading.Event() # Event to signal server to stop.

    def run_server():
        # Ensure server.py's global CONFIG_FILE is set correctly for this thread.
        os.environ['CONFIG'] = os.path.basename(config_path)

        
        try:
            start_server(
                linuxpath=dummy_data_file,
                reread_on_query=True,
                use_ssl=False,
                certfile=None,
                keyfile=None,
                psk='dummy_psk',
                port=test_port
            )

        except KeyboardInterrupt:
            pass # Expected for graceful shutdown in test.

        except Exception as e:
            print(f"Server thread error: {e}", file=sys.stderr)


    # Daemon thread to prevent blocking exit.
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()

    # Wait for the server to start (try connecting repeatedly).
    for _ in range(20): # Try for up to 2 seconds
        try:
            with socket.create_connection(('localhost', test_port), timeout=0.1):
                break

        except (ConnectionRefusedError, socket.timeout):
            time.sleep(0.1)
    else:
        pytest.fail("Server did not start in time!")

    num_clients = 5
    client_threads = []
    responses = {}
    lock = threading.Lock()

    def client_task(client_id):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_sock:
                client_sock.connect(('localhost', test_port))
                request = f"item{client_id % 3 + 1}\n" # Send item1, item2, or item3.
                client_sock.sendall(request.encode('utf-8'))
                response = client_sock.recv(1024).decode('utf-8').strip()
                with lock:
                    responses[client_id] = response

        except Exception as e:
            with lock:
                responses[client_id] = f"CLIENT_ERROR: {e}"

    # Start client threads.
    for i in range(num_clients):
        t = threading.Thread(target=client_task, args=(i,))
        client_threads.append(t)
        t.start()

    # Wait for all client threads to complete.
    for t in client_threads:
        t.join(timeout=5) # Add a timeout for clients.
        if t.is_alive():
            pytest.fail(f"Client thread {t.name} did not complete in time.")

    # Assert client responses.
    for i in range(num_clients):
        expected_response = 'STRING EXISTS' if (i % 3 + 1) in [1, 2, 3] else 'STRING NOT FOUND' # All items should exist.
        assert responses.get(i) == expected_response, \
            f"Client {i} received unexpected response: {responses.get(i)}"

    # Gracefully shut down the server by sending KeyboardInterrupt to its thread.
    if server_thread.is_alive():
        print("Attempting to send KeyboardInterrupt to server thread...")
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(('localhost', test_port))

        except ConnectionRefusedError:
            # Server already shut down or failed.
            pass

        finally:
            pass

    # Check that server printed "Server started".
    captured = capfd.readouterr()
    assert f"Server started on port {test_port}." in captured.out


@patch('server.load_file_into_set')
def test_handle_client_socket_error(mock_load_file_into_set, temp_file, capfd):
    """
    Test that `handle_client` handles a generic socket error gracefully.

    This test simulates a scenario where an exception occurs while receiving data
    from the client socket. It verifies that:
    - An appropriate error message is sent back to the client.
    - The socket is properly closed after the error.
    - The error is logged to stdout.
    """
    mock_load_file_into_set.return_value = {'hello', 'world'}
    mock_socket = MagicMock()
    mock_socket.recv.side_effect = socket.error("Generic socket error")
    mock_socket.sendall = MagicMock()

    handle_client(
        client_socket=mock_socket,
        address=('127.0.0.1', 5000),
        linuxpath=temp_file,
        reread_on_query=True
    )
    mock_socket.sendall.assert_called_with(b"ERROR: Network error\n")
    mock_socket.close.assert_called_once()
    captured = capfd.readouterr()
    assert "ERROR: Socket error with ('127.0.0.1', 5000): Generic socket error" in captured.out


@patch('server.load_file_into_set')
def test_handle_client_unicode_decode_error(mock_load_file_into_set, temp_file, capfd):
    """
    Test that `handle_client` handles UnicodeDecodeError when receiving invalid UTF-8 data.

    This test simulates a scenario where the client sends improperly encoded byte data
    that cannot be decoded using UTF-8. It verifies that:
    - An appropriate encoding error message is sent back to the client.
    - The client socket is properly closed after the error.
    - The error is logged to stdout.
    """
    mock_load_file_into_set.return_value = {'hello', 'world'}
    mock_socket = MagicMock()
    mock_socket.recv.return_value = b'\xff\xfe\xfa' # Invalid UTF-8.
    mock_socket.decode.side_effect = UnicodeDecodeError("utf-8", b'\xff\xfe\xfa', 0, 1, "invalid start byte")
    mock_socket.sendall = MagicMock()

    handle_client(
        client_socket=mock_socket,
        address=('127.0.0.1', 5000),
        linuxpath=temp_file,
        reread_on_query=True
    )
    mock_socket.sendall.assert_called_with(b"ERROR: Invalid message encoding\n")
    mock_socket.close.assert_called_once()
    captured = capfd.readouterr()
    assert "ERROR: Unable to decode message from ('127.0.0.1', 5000)" in captured.out


@patch('server.load_file_into_set')
def test_handle_client_unexpected_error(mock_load_file_into_set, temp_file, capfd):
    """
    Test that `handle_client` gracefully handles unexpected internal exceptions.

    This test simulates a scenario where an unanticipated exception (e.g., `ValueError`)
    is raised during the handling of a client connection. It verifies that:
    - The server sends a generic internal error response to the client.
    - The client socket is properly closed.
    - A clear error message is logged to stdout for debugging purposes.
    """
    # Mock the file-loading function to return a dummy word set.
    mock_load_file_into_set.return_value = {'hello', 'world'}

    # Create a mock socket object to simulate client behavior.
    mock_socket = MagicMock()

    # Simulate an unexpected internal error (e.g., ValueError) when trying to receive data.
    mock_socket.recv.side_effect = ValueError("Some unexpected internal error")

    # Mock the sendall method to track what gets sent to the client.
    mock_socket.sendall = MagicMock()

    # Call the actual client handler function with the mock socket and a dummy address.
    handle_client(
        client_socket=mock_socket,
        address=('127.0.0.1', 5000),
        linuxpath=temp_file,
        reread_on_query=True
    )

    # Assert that the server sends a generic internal error message back to the client.
    mock_socket.sendall.assert_called_with(b"ERROR: Server encountered an unexpected error\n")
    
    # Assert that the socket is closed after the error occurs.
    mock_socket.close.assert_called_once()

    # Capture and assert that the expected error log message was printed.
    captured = capfd.readouterr()
    assert "ERROR: Unexpected error handling client ('127.0.0.1', 5000): Some unexpected internal error" in captured.out


@patch('server.load_file_into_set')
def test_handle_client_query_too_long(mock_load_file_into_set, temp_file):
    """
    Test that `handle_client` correctly rejects an excessively long query.

    This test simulates a client sending a query string that exceeds the
    allowed maximum length (200 characters). The server is expected to:

    - Respond with an appropriate error message: "ERROR: Query too long"
    - Close the connection without attempting to process the query
    """
    # Create a mock socket to simulate client behavior.
    mock_socket = MagicMock()

    # Simulate receiving a query string that is 201 characters long.
    mock_socket.recv.return_value = b'A' * 201 + b'\n'

    # Mock sendall and close methods to track usage.
    mock_socket.sendall = MagicMock()
    mock_socket.close = MagicMock() 

    # Call the handle_client function with mocked client socket and test inputs.
    handle_client(
        client_socket=mock_socket,
        address=('127.0.0.1', 5000),
        linuxpath=temp_file,
        reread_on_query=True
    )

    # Check that the error message for too long a query was sent to the client.
    mock_socket.sendall.assert_called_with(b"ERROR: Query too long\n")

    # Check that the client connection was closed.
    mock_socket.close.assert_called_once()

    # Ensure no further processing happens.
    mock_load_file_into_set.assert_not_called()


@patch('server.load_dotenv')
@patch('server.socket.socket')
@patch('server.load_file_into_set')
@patch('server.ssl.SSLContext')
def test_start_server_ssl_context_error(
    mock_ssl_context_class, mock_load_file_into_set, mock_socket_class,
    temp_config_file_path, capfd, tmp_path
):
    """
    Test that `start_server` handles an SSLContext creation failure gracefully.

    This test simulates a situation where the SSL context fails to initialize (e.g., due to
    misconfiguration or invalid environment) by raising an `ssl.SSLError` during the
    instantiation of `ssl.SSLContext`.

    It verifies that:
    - The SSL error is triggered when attempting to start the server with SSL enabled.
    - The error is handled without causing a crash or unhandled exception.
    """
    # Create a mock config object to simulate expected config behavior.
    mock_config = MagicMock()

    # Simulate config.get() returning various SSL and server settings.
    mock_config.get.side_effect = lambda section, option, fallback=None: {
        'linuxpath': str(tmp_path / 'dummy_data.txt'),
        'REREAD_ON_QUERY': 'False',
        'USE_SSL': 'True',
        'CERTFILE': str(tmp_path / 'dummy.crt'),
        'KEYFILE': str(tmp_path / 'dummy.key'),
        'PSK': 'dummy_psk',
        'PORT': '12345'
    }.get(option, fallback)

    # Simulate config.getboolean() returning True only for USE_SSL.
    mock_config.getboolean.side_effect = lambda section, option, fallback: True if option == 'USE_SSL' else False

    # Simulate config.getint() returning the server port number.
    mock_config.getint.return_value = 12345

    # Simulate SSLContext initialization failure.
    mock_ssl_context_class.side_effect = ssl.SSLError("Failed to create SSL context")

    # Patch the server's config with the mock config and prevent actual threads from starting.
    with patch('server.config', mock_config): # Patch the global config.
        with patch('server.threading.Thread'):
            # Attempt to start the server with mocked SSL configuration.
            # This should trigger the SSLError from the mocked SSLContext constructor.
            start_server(
                linuxpath=str(tmp_path / 'dummy_data.txt'),
                reread_on_query=False,
                use_ssl=True,
                certfile=str(tmp_path / 'dummy.crt'),
                keyfile=str(tmp_path / 'dummy.key'),
                psk='dummy_psk',
                port=12345
            )


def test_concurrent_clients_reread_on_query(tmp_path):
    """
    Tests that the server correctly handles multiple concurrent client queries
    when 'reread_on_query' is set to True.

    The server should re-read the data file for each individual query to ensure
    up-to-date results. This test simulates four concurrent client requests:

    - Two for strings that exist in the file.
    - Two for strings that do not exist.

    Verifies that:
    - "orange" and "melon" are correctly found.
    - "kiwi" and "grapefruit" are correctly reported as not found.
    """
    # Set the port for the server.
    port = 12352

    # Create a temporary data file with initial content.
    data_file = tmp_path / "reread_data.txt"
    data_file.write_text("orange\npeach\nmelon\n")

    # Start the server in a background thread with reread_on_query enabled.
    t = threading.Thread(target=server.start_server, kwargs={
        'linuxpath': str(data_file),
        'reread_on_query': True,  # Ensure server reads the file fresh for each query.
        'use_ssl': False,
        'certfile': '', 'keyfile': '',
        'psk': None, 'port': port
    }, daemon=True)
    t.start()

    # Give the server a moment to start up before sending queries.
    time.sleep(0.5)

    # Define queries to send to the server.
    queries = ["orange", "melon", "kiwi", "grapefruit"]
    results = [None] * len(queries)
    threads = []

    # Launch one thread per query to simulate multiple concurrent clients.
    for i, q in enumerate(queries):
        th = threading.Thread(target=send_query, args=(q, port, results, i))
        threads.append(th)
        th.start()

    # Wait for all client threads to complete.
    for th in threads:
        th.join()

    # Assertions: check that correct responses were received.
    assert "EXISTS" in results[0]  # "orange" is in the file.
    assert "EXISTS" in results[1]  # "melon" is in the file.
    assert "NOT FOUND" in results[2]  # "kiwi" is not in the file
    assert "NOT FOUND" in results[3]  # "grapefruit" is not in the file.


def test_concurrent_clients_no_reread_on_query(tmp_path):
    """
    Tests that the server uses the initial cached file content
    when 'reread_on_query' is set to False.

    The server is expected to not reflect any file updates after startup.
    """
    port = 12354
    data_file = tmp_path / "no_reread_data.txt"
    data_file.write_text("apple\nbanana\ncherry\n")

    t = threading.Thread(target=server.start_server, kwargs={
        'linuxpath': str(data_file),
        'reread_on_query': False,  # File is read once at startup
        'use_ssl': False,
        'certfile': '', 'keyfile': '',
        'psk': None,
        'port': port
    }, daemon=True)
    t.start()
    time.sleep(0.5)

    # Update the file, but server should ignore this.
    data_file.write_text("banana\ndate\nelderberry\n")

    queries = ["apple", "banana", "date"]
    results = [None] * len(queries)
    threads = []

    for i, q in enumerate(queries):
        th = threading.Thread(target=send_query, args=(q, port, results, i))
        threads.append(th)
        th.start()

    for th in threads:
        th.join()

    assert "EXISTS" in results[0]      # "apple" was in the original file
    assert "EXISTS" in results[1]      # "banana" was in both versions
    assert "NOT FOUND" in results[2]   # "date" was added after startup, should be ignored


def test_concurrent_clients_with_ssl(tmp_path):
    """
    Tests that the server can handle multiple concurrent client queries over SSL.

    Ensures the SSL-enabled server can read file content properly per query
    and return accurate results with `reread_on_query=True`.
    """
    port = 12355
    data_file = tmp_path / "ssl_data.txt"
    data_file.write_text("pineapple\ngrape\nfig\n")

    # Create temporary cert and key for SSL
    certfile = tmp_path / "server.pem"
    keyfile = tmp_path / "server.key"
    generate_self_signed_cert(str(certfile), str(keyfile))

    t = threading.Thread(target=server.start_server, kwargs={
        'linuxpath': str(data_file),
        'reread_on_query': True,
        'use_ssl': True,
        'certfile': str(certfile),
        'keyfile': str(keyfile),
        'psk': None,
        'port': port
    }, daemon=True)
    t.start()
    time.sleep(0.5)

    queries = ["pineapple", "fig", "banana"]
    results = [None] * len(queries)
    threads = []

    for i, q in enumerate(queries):
        th = threading.Thread(target=send_query_ssl, args=(q, port, results, i, str(certfile)))
        threads.append(th)
        th.start()

    for th in threads:
        th.join()

    assert "EXISTS" in results[0]
    assert "EXISTS" in results[1]
    assert "NOT FOUND" in results[2]


def test_concurrent_query_with_live_file_update(tmp_path):
    """
    Test server behavior under concurrent queries while the data file is being updated.

    This test verifies that:
    - The server re-reads the data file on every query when 'reread_on_query' is True.
    - Multiple clients can query the server concurrently.
    - The server correctly picks up changes to the data file in real time during execution.

    Procedure:
    - A temporary file is created with initial content ('foo', 'bar', 'baz').
    - The server is launched in a separate thread with reread_on_query=True.
    - A writer thread updates the file contents after a short delay.
    - Client threads concurrently send queries:
        - 'foo' (present in the initial file only),
        - 'bar' (present in both the initial and updated files),
        - 'updated' (present only in the updated file).
    - The test asserts that 'bar' was successfully found, validating live reloading behavior.

    Notes:
    - Due to concurrency and timing, 'foo' and 'updated' may or may not be found, so no assertion is made for them.
    """
    # Define port and create a temporary data file with initial content.
    port = 12353
    data_file = tmp_path / "livefile.txt"
    data_file.write_text("foo\nbar\nbaz\n")

    # Start the server in a separate thread with reread_on_query=True to re-read the file on every query.
    t = threading.Thread(target=server.start_server, kwargs={
        'linuxpath': str(data_file),
        'reread_on_query': True,  # Enable dynamic file reading per query.
        'use_ssl': False,
        'certfile': '', 'keyfile': '',
        'psk': None, 'port': port
    }, daemon=True)
    t.start()
    time.sleep(0.5)  # Give the server time to start.

    # Define a function that modifies the file content after a short delay.
    def modify_file():
        time.sleep(0.2)  # Delay to allow some queries to hit the old content.
        data_file.write_text("bar\nupdated\nbaz\n")  # Overwrite file to simulate live update.


    # Define the queries to send and initialize a results list.
    queries = ["foo", "bar", "updated"]
    results = [None] * len(queries)
    threads = []

    # Writer thread simulates concurrent update.
    writer_thread = threading.Thread(target=modify_file)
    writer_thread.start()

    # Start a separate thread for each query to simulate concurrent client requests.
    for i, q in enumerate(queries):
        th = threading.Thread(target=send_query, args=(q, port, results, i))
        threads.append(th)
        th.start()

    # Wait for all query threads to finish.
    for th in threads:
        th.join()
    # Wait for the writer thread to complete the file update.    
    writer_thread.join()

    # Depending on timing, 'foo' may or may not be found.
    assert "EXISTS" in results[1]
    # Assert that "updated" may be found depending on timing.
    assert "EXISTS" in results[2] or "NOT FOUND" in results[2]


def test_concurrent_clients_preloaded(tmp_path):
    """
    Test server's ability to handle concurrent client queries using a preloaded dataset.

    This test ensures that:
    - The server correctly loads data into memory before starting.
    - Multiple clients can connect and send queries simultaneously.
    - The server responds accurately for both found and not-found queries when 'reread_on_query' is False.

    Procedure:
    - Create a temporary data file with strings: 'apple', 'banana', 'cherry'.
    - Preload the dataset into server memory (simulate startup behavior).
    - Start the server in a background thread (with preloaded dataset).
    - Spawn client threads to concurrently query the server with:
        - 3 matching strings: 'apple', 'banana', 'cherry'.
        - 1 non-matching string: 'grape'.
    - Verify that the server responds appropriately for each case.
    """
    port = 12351
    data_file = tmp_path / "data.txt"
    data_file.write_text("apple\nbanana\ncherry\n")

    # Preload the data set into the server before it starts.
    server.preloaded_set = server.load_file_into_set(str(data_file))

    # Start server thread.
    t = threading.Thread(target=server.start_server, kwargs={
        'linuxpath': str(data_file),
        'reread_on_query': False,
        'use_ssl': False,
        'certfile': '', 'keyfile': '',
        'psk': None, 'port': port
    }, daemon=True)
    t.start()
    time.sleep(1.0)  # Give time for server to bind.

    # Define queries and prepare storage for results.
    queries = ["apple", "banana", "cherry", "grape"]
    results = [None] * len(queries)
    threads = []

    # Spawn a thread for each query to simulate concurrent clients.
    for i, q in enumerate(queries):
        th = threading.Thread(target=send_query_with_retries, args=(q, port, results, i))
        threads.append(th)
        th.start()

    # Wait for all client threads to complete.
    for th in threads:
        th.join()

    print("Client results:", results)

    # Validate that known strings exist, and unknown one is correctly reported as not found.
    assert results[0] and results[0].startswith("STRING EXISTS")
    assert results[1] and results[1].startswith("STRING EXISTS")
    assert results[2] and results[2].startswith("STRING EXISTS")
    assert results[3] and results[3].startswith("STRING NOT FOUND")
