"""Local SSH handshake tests, including actual hardware when requested."""
import os
import socket
import threading
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
import paramiko

from ssh_support import connect_token, fingerprint, probe_host, validate_connection
from token_tool import Token, TokenSSHKey


class SoftwareToken:
    def __init__(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def public_key(self):
        return self.key.public_key()

    def sign_digest(self, digest):
        return self.key.sign(digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))


class TestSSH(unittest.TestCase):
    def test_fields(self):
        self.assertEqual(validate_connection(' localhost ', '22', ' user '), ('localhost', 22, 'user'))
        for args in [('', '22', 'u'), ('host', '0', 'u'), ('host', 'bad', 'u'), ('https://host', '22', 'u')]:
            with self.assertRaises(ValueError):
                validate_connection(*args)

    def test_loopback(self):
        self.exercise(SoftwareToken())

    @unittest.skipUnless(os.environ.get('EPASS_HARDWARE_TEST') == '1', 'Hardware test opt-in')
    def test_hardware_loopback(self):
        token = Token(Path(__file__).parent / 'libusb-1.0.dll')
        try:
            token.exchange(1)
            token.login('12345678')
            self.exercise(token)
        finally:
            token.close()

    def exercise(self, token):
        """Verify probe, signature-based authentication and host-key rejection."""
        host_key = paramiko.RSAKey.generate(2048)
        approved = TokenSSHKey(token).asbytes()
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(3)
        listener.settimeout(15)
        port = listener.getsockname()[1]
        failures = []
        authenticated = threading.Event()

        class Server(paramiko.ServerInterface):
            def get_allowed_auths(self, username):
                return 'publickey'

            def check_auth_publickey(self, username, key):
                if username == 'testuser' and key.asbytes() == approved:
                    authenticated.set()
                    return paramiko.AUTH_SUCCESSFUL
                return paramiko.AUTH_FAILED

        def serve():
            try:
                for _ in range(3):
                    sock, _ = listener.accept()
                    transport = paramiko.Transport(sock)
                    transport.add_server_key(host_key)
                    try:
                        transport.start_server(server=Server())
                        while transport.is_active():
                            threading.Event().wait(0.02)
                    except (EOFError, paramiko.SSHException, ConnectionResetError):
                        pass
                    finally:
                        transport.close()
            except Exception as error:
                failures.append(error)
            finally:
                listener.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        observed = probe_host('127.0.0.1', port)
        self.assertEqual(fingerprint(observed), fingerprint(host_key))
        client = connect_token('127.0.0.1', port, 'testuser', observed, token)
        self.assertTrue(client.get_transport().is_authenticated())
        self.assertTrue(authenticated.is_set())
        client.close()
        with self.assertRaises(paramiko.BadHostKeyException):
            connect_token('127.0.0.1', port, 'testuser', paramiko.RSAKey.generate(2048), token)
        thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])
