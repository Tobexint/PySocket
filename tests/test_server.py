import pytest
import tempfile
import os
import sys
from unittest.mock import patch, MagicMock
import socket
import ssl

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


from server import (
    load_config,
    load_file_into_set,
    search_string_in_set,
    handle_client,
    start_server
)


@pytest.fixture
def temp_file():
    """Create a temporary file for testing"""
    with tempfile.NamedTemporaryFile(delete=False, mode='w', encoding='utf-8') as f:
        f.write('hello\nworld\n')
        temp_path = f.name
    yield temp_path
    os.remove(temp_path)


def test_load_config_success(monkeypatch, tmp_path):
    """Test successful loading of configuration"""

    dummy_config_content = """
    [DEFAULT]
    linuxpath = dummy_path
    REREAD_ON_QUERY = True
    USE_SSL = False
    CERTFILE = dummy_crt
    KEYFILE = dummy_key
    PSK = dummy_psk
    PORT = 5555
    """

    with tempfile.NamedTemporaryFile(delete=False, mode='w', encoding='utf-8') as temp_config:
        temp_config.write(dummy_config_content)
        config_path = temp_config.name

    # Mock os.getenv to return the temp config file
    monkeypatch.setenv('CONFIG', os.path.basename(config_path))

    # Patch configparser to read our dummy config
    with patch('server.config.read', return_value=None), \
         patch('server.config', autospec=True) as mock_config, \
         patch('server.os.path.isfile', return_value=True):

        mock_config.__getitem__.side_effect = lambda key: {
            'linuxpath': tmp_path / 'dummy.txt',
            'REREAD_ON_QUERY': 'True',
            'USE_SSL': 'False',
            'CERTFILE': tmp_path / 'dummy.crt',
            'KEYFILE': tmp_path / 'dummy.key',
            'PSK': 'dummy_psk',
            'PORT': '5555'
        }

        mock_config.getboolean.side_effect = lambda section, option, fallback: True if option == 'REREAD_ON_QUERY' else False
        mock_config.get.side_effect = lambda section, option, fallback=None: 'dummy_psk'
        mock_config.getint.side_effect = lambda section, option, fallback=None: 5555

        linuxpath, reread_on_query, use_ssl, certfile, keyfile, psk, port = load_config(config_path)

        assert linuxpath.endswith('dummy.txt')
        assert reread_on_query is True
        assert use_ssl is False
        assert psk == 'dummy_psk'
        assert port == 5555


def test_load_file_into_set_success(temp_file):
    """Test loading a file into a set"""
    result = load_file_into_set(temp_file)
    assert result == {'hello', 'world'}


def test_load_file_into_set_not_found(tmp_path):
    """Test loading a nonexistent file"""
    fake_file = tmp_path / "nonexistent.txt"
    with pytest.raises(FileNotFoundError):
        load_file_into_set(fake_file)


def test_load_file_into_set_is_directory(tmp_path):
    """Test loading a directory instead of a file"""
    with pytest.raises(IsADirectoryError):
        load_file_into_set(tmp_path)


def test_search_string_in_set_found():
    """Test search string found"""
    lines_set = {'hello', 'world'}
    assert search_string_in_set(lines_set, 'hello') is True


def test_search_string_in_set_not_found():
    """Test search string not found"""
    lines_set = {'hello', 'world'}
    assert search_string_in_set(lines_set, 'test') is False


@patch('server.load_file_into_set')
def test_handle_client_string_exists(mock_load_file_into_set, temp_file):
    """Test handling a client that sends a string that exists"""
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
    """Test handling a client that sends a string that doesn't exist"""
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
    """Test starting server without SSL"""

    mock_socket_instance = MagicMock()
    mock_socket_class.return_value = mock_socket_instance
    mock_socket_instance.accept.side_effect = KeyboardInterrupt  # Stop server after one accept

    # preload file set
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
    """Test starting server with SSL"""

    # Create dummy cert and key files in tmp_path
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
    file_path.write_text("")  # Create empty file
    assert load_file_into_set(str(file_path)) == set()


def test_load_file_into_set_blank_lines(tmp_path):
    """Test loading a file with only blank lines returns empty set."""
    file_path = tmp_path / "blank.txt"
    file_path.write_text("\n\n   \n\n")  # Only blank lines
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
    file_path.write_text("  apple  \n\tbanana\t\norange \n")
    result = load_file_into_set(str(file_path))
    assert result == {"apple", "banana", "orange"}


def test_load_file_into_set_unicode_decode_error(tmp_path):
    """Test UnicodeDecodeError is raised for invalid UTF-8 file."""
    file_path = tmp_path / "invalid_utf8.txt"
    # Write invalid UTF-8 bytes
    file_path.write_bytes(b'\xff\xfe\xfa')
    with pytest.raises(UnicodeDecodeError):
        load_file_into_set(str(file_path))
