import os
import configparser
import importlib
import socket
import ssl
import sys
import tempfile
import time
import threading
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

    mock_socket.sendall.assert_called_with(b'STRING NOT FOUND')
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
    """Test loading an empty file returns an empty set."""
    file_path = tmp_path / "empty.txt"
    file_path.write_text("")
    assert load_file_into_set(str(file_path)) == set()


def test_load_file_into_set_blank_lines(tmp_path):
    """Test loading a file with only blank lines returns empty set."""
    file_path = tmp_path / "blank.txt"
    file_path.write_text("\n\n    \n\n")
    assert load_file_into_set(str(file_path)) == set()


def test_load_file_into_set_duplicates(tmp_path):
    """Test file with duplicate lines results in unique entries."""
    file_path = tmp_path / "duplicates.txt"
    file_path.write_text("apple\nbanana\napple\nbanana\norange\n")
    result = load_file_into_set(str(file_path))
    assert result == {"apple", "banana", "orange"}


def test_load_file_into_set_strip_whitespace(tmp_path):
    """Test lines are stripped of leading/trailing whitespace."""
    file_path = tmp_path / "whitespace.txt"
    file_path.write_text("  apple   \n\tbanana\t\norange \n")
    result = load_file_into_set(str(file_path))
    assert result == {"apple", "banana", "orange"}


def test_load_file_into_set_unicode_decode_error(tmp_path):
    """Test UnicodeDecodeError is raised for invalid UTF-8 file."""
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
    monkeypatch.setenv('CONFIG', 'non_existent.ini')
    with patch('server.os.path.isfile', return_value=False), \
         patch('server.configparser.ConfigParser') as MockConfigParser:
        # Create a mock for config.read() to prevent it from looking for a real file.
        mock_config_instance = MockConfigParser.return_value
        mock_config_instance.read.return_value = [] # No files read.

        with pytest.raises(RuntimeError) as excinfo:
            load_config()
        assert "Error accessing a configured file" in str(excinfo.value)
        assert "not found" in str(excinfo.value)


def test_load_config_os_error(monkeypatch, tmp_path):
    config_path = tmp_path / "os_error_config.ini"
    config_path.write_text("[DEFAULT]\nlinuxpath=dummy")
    monkeypatch.setenv('CONFIG', os.path.basename(config_path))

    with patch('server.os.path.isfile', side_effect=OSError("Permission denied")), \
         patch('server.configparser.ConfigParser'):
        with pytest.raises(RuntimeError) as excinfo:
            load_config()
        assert "Operating system error while accessing config file" in str(excinfo.value)
        assert "Permission denied" in str(excinfo.value)


@patch('server.load_file_into_set')
def test_handle_client_connection_reset_error(mock_load_file_into_set, temp_file, capfd):
    mock_load_file_into_set.return_value = {'hello', 'world'}
    mock_socket = MagicMock()
    mock_socket.recv.side_effect = ConnectionResetError("Client reset")

    handle_client(
        client_socket=mock_socket,
        address=('127.0.0.1', 5000),
        linuxpath=temp_file,
        reread_on_query=True
    )
    mock_socket.close.assert_called_once()
    captured = capfd.readouterr()
    assert "WARNING: Connection reset by client ('127.0.0.1', 5000)" in captured.out


@patch('server.load_file_into_set')
def test_handle_client_socket_timeout(mock_load_file_into_set, temp_file, capfd):
    mock_load_file_into_set.return_value = {'hello', 'world'}
    mock_socket = MagicMock()
    mock_socket.recv.side_effect = socket.timeout("Timed out")
    mock_socket.sendall = MagicMock()

    handle_client(
        client_socket=mock_socket,
        address=('127.0.0.1', 5000),
        linuxpath=temp_file,
        reread_on_query=True
    )
    mock_socket.sendall.assert_called_with(b"ERROR: Connection timed out\n")
    mock_socket.close.assert_called_once()
    captured = capfd.readouterr()
    assert "WARNING: Socket timeout with client ('127.0.0.1', 5000)" in captured.out


# Test `handle_client` with null bytes in query.
@patch('server.load_file_into_set')
def test_handle_client_null_bytes_in_query(mock_load_file_into_set, temp_file):
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
    mock_socket.sendall.assert_called_with(b'STRING EXISTS\n') # Null bytes should be removed.
    mock_socket.close.assert_called_once()


@patch('server.load_dotenv')
@patch('server.socket.socket')
@patch('server.load_file_into_set')
@patch('server.ssl.SSLContext')
def test_start_server_ssl_cert_load_error(
    mock_ssl_context_class, mock_load_file_into_set, mock_socket_class,
    temp_config_file_path, capfd, tmp_path
):
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


# Helper function to find a free port.
def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('localhost', 0))
        return s.getsockname()[1]

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
    mock_load_file_into_set.return_value = {'hello', 'world'}
    mock_socket = MagicMock()
    mock_socket.recv.side_effect = ValueError("Some unexpected internal error") # Simulate an unexpected error.
    mock_socket.sendall = MagicMock()

    handle_client(
        client_socket=mock_socket,
        address=('127.0.0.1', 5000),
        linuxpath=temp_file,
        reread_on_query=True
    )
    mock_socket.sendall.assert_called_with(b"ERROR: Server encountered an unexpected error\n")
    mock_socket.close.assert_called_once()
    captured = capfd.readouterr()
    assert "ERROR: Unexpected error handling client ('127.0.0.1', 5000): Some unexpected internal error" in captured.out


@patch('server.load_file_into_set')
def test_handle_client_query_too_long(mock_load_file_into_set, temp_file):
    mock_socket = MagicMock()
    mock_socket.recv.return_value = b'A' * 201 + b'\n' # Query over 200 chars.
    mock_socket.sendall = MagicMock()
    mock_socket.close = MagicMock() 

    handle_client(
        client_socket=mock_socket,
        address=('127.0.0.1', 5000),
        linuxpath=temp_file,
        reread_on_query=True
    )

    mock_socket.sendall.assert_called_with(b"ERROR: Query too long\n")
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
    mock_config = MagicMock()
    mock_config.get.side_effect = lambda section, option, fallback=None: {
        'linuxpath': str(tmp_path / 'dummy_data.txt'),
        'REREAD_ON_QUERY': 'False',
        'USE_SSL': 'True',
        'CERTFILE': str(tmp_path / 'dummy.crt'),
        'KEYFILE': str(tmp_path / 'dummy.key'),
        'PSK': 'dummy_psk',
        'PORT': '12345'
    }.get(option, fallback)
    mock_config.getboolean.side_effect = lambda section, option, fallback: True if option == 'USE_SSL' else False
    mock_config.getint.return_value = 12345

    # Simulate SSLContext initialization failure.
    mock_ssl_context_class.side_effect = ssl.SSLError("Failed to create SSL context")

    with patch('server.config', mock_config): # Patch the global config.
        with patch('server.threading.Thread'):
            start_server(
                linuxpath=str(tmp_path / 'dummy_data.txt'),
                reread_on_query=False,
                use_ssl=True,
                certfile=str(tmp_path / 'dummy.crt'),
                keyfile=str(tmp_path / 'dummy.key'),
                psk='dummy_psk',
                port=12345
            )


def send_query(query, port, results, idx):
    try:
        with socket.create_connection(('localhost', port), timeout=3) as s:
            s.sendall(query.encode())
            results[idx] = s.recv(1024).decode()
    except Exception as e:
        results[idx] = str(e)


def test_concurrent_clients_reread_on_query(tmp_path):
    port = 12352
    data_file = tmp_path / "reread_data.txt"
    data_file.write_text("orange\npeach\nmelon\n")

    t = threading.Thread(target=server.start_server, kwargs={
        'linuxpath': str(data_file),
        'reread_on_query': True,
        'use_ssl': False,
        'certfile': '', 'keyfile': '',
        'psk': None, 'port': port
    }, daemon=True)
    t.start()
    time.sleep(0.5)

    queries = ["orange", "melon", "kiwi", "grapefruit"]
    results = [None] * len(queries)
    threads = []

    for i, q in enumerate(queries):
        th = threading.Thread(target=send_query, args=(q, port, results, i))
        threads.append(th)
        th.start()

    for th in threads:
        th.join()

    assert "EXISTS" in results[0]
    assert "EXISTS" in results[1]
    assert "NOT FOUND" in results[2]
    assert "NOT FOUND" in results[3]


def test_concurrent_query_with_live_file_update(tmp_path):
    port = 12353
    data_file = tmp_path / "livefile.txt"
    data_file.write_text("foo\nbar\nbaz\n")

    t = threading.Thread(target=server.start_server, kwargs={
        'linuxpath': str(data_file),
        'reread_on_query': True,
        'use_ssl': False,
        'certfile': '', 'keyfile': '',
        'psk': None, 'port': port
    }, daemon=True)
    t.start()
    time.sleep(0.5)

    def modify_file():
        time.sleep(0.2)
        data_file.write_text("bar\nupdated\nbaz\n")

    queries = ["foo", "bar", "updated"]
    results = [None] * len(queries)
    threads = []

    # Writer thread simulates concurrent update.
    writer_thread = threading.Thread(target=modify_file)
    writer_thread.start()

    for i, q in enumerate(queries):
        th = threading.Thread(target=send_query, args=(q, port, results, i))
        threads.append(th)
        th.start()

    for th in threads:
        th.join()
    writer_thread.join()

    # Depending on timing, 'foo' may or may not be found.
    assert "EXISTS" in results[1]
    assert "EXISTS" in results[2] or "NOT FOUND" in results[2]


def test_concurrent_clients_preloaded(tmp_path):
    port = 12351
    data_file = tmp_path / "data.txt"
    data_file.write_text("apple\nbanana\ncherry\n")

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

    queries = ["apple", "banana", "cherry", "grape"]
    results = [None] * len(queries)
    threads = []

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

    for i, q in enumerate(queries):
        th = threading.Thread(target=send_query_with_retries, args=(q, port, results, i))
        threads.append(th)
        th.start()

    for th in threads:
        th.join()

    print("Client results:", results)

    assert results[0] and results[0].startswith("STRING EXISTS")
    assert results[1] and results[1].startswith("STRING EXISTS")
    assert results[2] and results[2].startswith("STRING EXISTS")
    assert results[3] and results[3].startswith("STRING NOT FOUND")

