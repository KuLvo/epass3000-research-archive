"""Profile storage and non-destructive key installation tests."""
import io
from pathlib import Path
import stat
import tempfile
import unittest
from types import SimpleNamespace
from ssh_cli import append_public_key, load_profiles, save_profiles


class FakeFile(io.BytesIO):
    def __init__(self, server, value, append):
        super().__init__(value)
        self.server = server
        self.append = append
        if append:
            self.seek(0, 2)

    def close(self):
        if self.append and not self.closed:
            self.server.content = self.getvalue()
        super().close()


class FakeSFTP:
    def __init__(self):
        self.content = b'existing-key-no-newline'
        self.modes = {}

    def normalize(self, path):
        return '/home/test'

    def lstat(self, path):
        return SimpleNamespace(st_mode=stat.S_IFDIR if path.endswith('/.ssh') else stat.S_IFREG)

    def chmod(self, path, mode):
        self.modes[path] = mode

    def open(self, path, mode):
        return FakeFile(self, self.content, mode == 'ab')


class CLITests(unittest.TestCase):
    def test_profile_roundtrip(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'servers.json'
            self.assertEqual(load_profiles(path), [])
            records = [dict(name='中文服务器', host='localhost', port=22, user='test')]
            save_profiles(records, path)
            self.assertEqual(load_profiles(path), records)
            save_profiles([], path)
            self.assertEqual(load_profiles(path), [])

    def test_append_idempotent(self):
        sftp = FakeSFTP()
        public = 'ssh-rsa AAAATEST epass3000'
        self.assertTrue(append_public_key(sftp, public))
        self.assertEqual(sftp.content, b'existing-key-no-newline\nssh-rsa AAAATEST epass3000\n')
        self.assertFalse(append_public_key(sftp, public))
        self.assertEqual(sftp.modes['/home/test/.ssh/authorized_keys'], 0o600)

    def test_existing_restricted_key_preserved(self):
        sftp = FakeSFTP()
        sftp.content = b'from="127.0.0.1" ssh-rsa AAAATEST old\n'
        self.assertFalse(append_public_key(sftp, 'ssh-rsa AAAATEST new'))
        self.assertEqual(sftp.content, b'from="127.0.0.1" ssh-rsa AAAATEST old\n')

    def test_symlink_rejected(self):
        sftp = FakeSFTP()
        sftp.lstat = lambda path: SimpleNamespace(st_mode=stat.S_IFLNK)
        with self.assertRaises(ValueError):
            append_public_key(sftp, 'ssh-rsa AAAATEST new')
