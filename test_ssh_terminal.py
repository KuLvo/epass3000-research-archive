"""Terminal byte preservation, resize and trust-store tests."""
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from unittest.mock import patch

import paramiko
from ssh_terminal import relay, trusted_host, write_bytes


class TerminalTests(unittest.TestCase):
    def test_relay(self):
        sent = threading.Event()
        sequence = '中文'.encode() + b'\x1b[A\x03\r'

        class Channel:
            def __init__(self):
                self.sizes = []
                self.closed = False
                self.sent = b''
                self.reads = 0

            def settimeout(self, timeout):
                pass

            def sendall(self, data):
                self.sent += data

            def shutdown_write(self):
                sent.set()

            def recv(self, size):
                if not sent.wait(2):
                    raise socket.timeout()
                self.reads += 1
                return b'\x1b[2J\x1b[Hhello' if self.reads == 1 else b''

            def resize_pty(self, **kwargs):
                self.sizes.append(kwargs)

            def close(self):
                self.closed = True

        channel = Channel()
        inputs = iter([sequence, b''])
        dimensions = iter([(80, 24), (120, 40), (120, 40)])
        output = []
        relay(channel, lambda: next(inputs), output.append, lambda: next(dimensions))
        self.assertEqual(channel.sent, sequence)
        self.assertEqual(output, [b'\x1b[2J\x1b[Hhello'])
        self.assertEqual(channel.sizes, [{'width': 120, 'height': 40}])
        self.assertTrue(channel.closed)

    def test_trust_required(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'known'
            with self.assertRaisesRegex(ValueError, '尚未确认'):
                trusted_host(path, 'localhost', 2222)
            key = paramiko.RSAKey.generate(2048)
            known = paramiko.HostKeys()
            known.add('[localhost]:2222', key.get_name(), key)
            known.save(str(path))
            self.assertEqual(trusted_host(path, 'localhost', 2222), key)

    def test_partial_write(self):
        with patch('ssh_terminal.os.write', side_effect=[2, 1]) as write:
            write_bytes(1, b'abc')
            self.assertEqual(write.call_args_list[1].args, (1, b'c'))
