"""SSH host verification and hardware-backed connection helpers."""
import base64
import hashlib
import socket

import paramiko
from token_tool import TokenSSHKey


def fingerprint(key):
    """Return the standard OpenSSH SHA256 host fingerprint."""
    return 'SHA256:' + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')


def validate_connection(host, port, user):
    """Validate connection fields before any network operation."""
    if not host.strip() or not user.strip():
        raise ValueError('请填写服务器地址和用户名。')
    if any(character.isspace() for character in host.strip()) or '://' in host:
        raise ValueError('服务器地址只填写主机名或 IP，不要填写网址或空格。')
    try:
        value = int(port)
    except ValueError as error:
        raise ValueError('端口必须是 1 到 65535 的整数。') from error
    if not 1 <= value <= 65535:
        raise ValueError('端口必须是 1 到 65535 的整数。')
    return host.strip(), value, user.strip()


def probe_host(host, port):
    """Read the host key without authenticating or sending a PIN."""
    with socket.create_connection((host, port), timeout=10) as sock:
        transport = paramiko.Transport(sock)
        try:
            transport.start_client(timeout=10)
            return transport.get_remote_server_key()
        finally:
            transport.close()


def connect_token(host, port, user, expected_key, token):
    """Authenticate only to the exact host key approved by the user."""
    client = paramiko.SSHClient()
    name = host if port == 22 else f'[{host}]:{port}'
    client.get_host_keys().add(name, expected_key.get_name(), expected_key)
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect(host, port=port, username=user, pkey=TokenSSHKey(token),
                       allow_agent=False, look_for_keys=False, timeout=10,
                       banner_timeout=10, auth_timeout=20,
                       disabled_algorithms={'pubkeys': ['ssh-rsa', 'rsa-sha2-512']})
        return client
    except Exception:
        client.close()
        raise
