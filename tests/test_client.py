import sys
import pytest
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from unittest.mock import patch, MagicMock
import socket
import ssl
from client import send_request, create_ssl_context
from dotenv import load_dotenv


# Mock Configuration
HOST = "127.0.0.1"
PORT = 12345

@pytest.fixture
def mock_socket():
    mock_sock = MagicMock()
    mock_sock.recv.return_value = b"MOCK RESPONSE"
    return mock_sock

@pytest.fixture
def mock_ssl_socket():
    mock_ssl_sock = MagicMock()
    mock_ssl_sock.recv.return_value = b"MOCK SSL RESPONSE"
    return mock_ssl_sock

# Test sending a request successfully without SSL
@patch("client.create_ssl_context", return_value=None)
@patch("socket.create_connection")
def test_send_request_no_ssl(mock_create_connection, mock_create_ssl_context):
    mock_socket = MagicMock()
    mock_socket.recv.return_value = b"MOCK RESPONSE"
    mock_create_connection.return_value.__enter__.return_value = mock_socket
    response = send_request("test query")
    assert response == "MOCK RESPONSE"
    #mock_socket.sendall.assert_called_with(b"test query")

# Test sending a request successfully with SSL
@patch("socket.create_connection")
@patch("ssl.create_default_context")
def test_send_request_with_ssl(mock_ssl_context, mock_create_connection, mock_ssl_socket):
    mock_create_connection.return_value.__enter__.return_value = mock_ssl_socket
    mock_ssl_context.return_value.wrap_socket.return_value.__enter__.return_value = mock_ssl_socket
    
    response = send_request("test query")
    assert response == "MOCK SSL RESPONSE"
    mock_ssl_socket.sendall.assert_called_with(b"test query")

# Test connection reset error
@patch("socket.create_connection", side_effect=ConnectionResetError)
def test_send_request_connection_reset(mock_create_connection):
    response = send_request("test query")
    assert response == "CONNECTION RESET ERROR"

# Test connection refused error
@patch("socket.create_connection", side_effect=ConnectionRefusedError)
def test_send_request_connection_refused(mock_create_connection):
    response = send_request("test query")
    assert response == "CONNECTION REFUSED"

# Test connection timeout error
@patch("socket.create_connection", side_effect=socket.timeout)
def test_send_request_timeout(mock_create_connection):
    response = send_request("test query")
    assert response == "CONNECTION TIMEOUT"

# Test generic socket error
@patch("socket.create_connection", side_effect=socket.error("Socket failure"))
def test_send_request_socket_error(mock_create_connection):
    response = send_request("test query")
    assert response == "SOCKET ERROR"


# Test unexpected error
@patch("socket.create_connection", side_effect=Exception("Unexpected failure"))
def test_send_request_unexpected_error(mock_create_connection):
    response = send_request("test query")
    assert response == "UNKNOWN ERROR"


# Test ssl handshake failure
@patch("socket.create_connection")
def test_send_request_ssl_handshake_failure(mock_create_connection):
    mock_socket = MagicMock()
    mock_create_connection.return_value.__enter__.return_value = mock_socket

    mock_ssl_context = MagicMock()
    mock_ssl_context.wrap_socket.side_effect = ssl.SSLError("Handshake failed")

    with patch("client.create_ssl_context", return_value=mock_ssl_context):
        response = send_request("test query")

    assert response == "SSL HANDSHAKE ERROR"


@pytest.fixture
def mock_ssl_context(monkeypatch):
    mock_context = MagicMock()
    monkeypatch.setattr("client.ssl.create_default_context", lambda: mock_context)
    return mock_context

@pytest.fixture
def mock_config(monkeypatch):
    monkeypatch.setattr("client.config", {"DEFAULT": {"CERTFILE": "certfile.crt", "KEYFILE": "keyfile.key"}})

@pytest.fixture
def mock_path_join(monkeypatch, tmp_path):
    fake_cert_path = tmp_path / "certfile.crt"
    monkeypatch.setattr("client.create_ssl_context", lambda: str(fake_cert_path))
    yield

@pytest.fixture
def disable_ssl(monkeypatch):
    monkeypatch.setattr("client.USE_SSL", False)

@pytest.fixture
def enable_ssl(monkeypatch):
    monkeypatch.setattr("client.USE_SSL", True)

class TestCreateSSLContext:
    def test_ssl_disabled_returns_none(self, disable_ssl):
        assert create_ssl_context() is None


    def test_ssl_enabled_successful_context(self, monkeypatch, tmp_path):
        # Create dummy cert and key files in tmp_path
        certfile = tmp_path / "certfile.crt"
        keyfile = tmp_path / "keyfile.crt"
        certfile.write_text("dummy cert")
        keyfile.write_text("dummy key")

        # Patch config['DEFAULT'] to point to our dummy cert/key filenames
        import client
        monkeypatch.setitem(client.config['DEFAULT'], 'CERTFILE', str(certfile))
        monkeypatch.setitem(client.config['DEFAULT'], 'KEYFILE', str(keyfile))
        monkeypatch.setattr(client, 'BASE_DIR', str(tmp_path))

        monkeypatch.setattr(client, 'USE_SSL', True)


        # Patch ssl context methods
        with patch('client.ssl.create_default_context') as mock_create_ctx:
            mock_context = mock_create_ctx.return_value

            context = client.create_ssl_context()

            assert context is mock_context
            mock_create_ctx.assert_called_once()
            mock_context.load_verify_locations.assert_called_once_with(str(certfile))
            mock_context.load_cert_chain.assert_called_once_with(str(certfile), str(keyfile))
            assert mock_context.check_hostname is False
            assert mock_context.verify_mode == ssl.CERT_REQUIRED

    def test_ssl_enabled_load_cert_chain_failure(self, enable_ssl, mock_path_join, mock_config, monkeypatch):
        mock_context = MagicMock()
        mock_context.load_verify_locations.side_effect = ssl.SSLError("Mock SSL error")

        monkeypatch.setattr("client.ssl.create_default_context", lambda: mock_context)

        context = create_ssl_context()

        assert context is None
