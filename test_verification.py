"""Check actual file verification and selection failures."""
from pathlib import Path
import tempfile
import unittest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from verification import suggested_paths, verify_paths


class VerificationTests(unittest.TestCase):
    def test_files_and_errors(self):
        with tempfile.TemporaryDirectory() as folder:
            original = Path(folder) / '中文文件.txt'
            original.write_bytes(b'original')
            signature = Path(str(original) + '.sig')
            public = Path(str(original) + '.public.pem')
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            signature.write_bytes(key.sign(b'original', padding.PKCS1v15(), hashes.SHA256()))
            public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
            paths = tuple(map(str, (original, signature, public)))
            self.assertEqual(suggested_paths(str(original)), paths[1:])
            verify_paths(*paths)
            original.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, '不匹配'):
                verify_paths(*paths)
            with self.assertRaisesRegex(ValueError, '尚未选择'):
                verify_paths('', paths[1], paths[2])
            with self.assertRaisesRegex(ValueError, '不同文件'):
                verify_paths(paths[0], paths[0], paths[2])
            signature.write_bytes(b'bad')
            with self.assertRaisesRegex(ValueError, '长度'):
                verify_paths(*paths)
            public.write_bytes(b'bad')
            with self.assertRaisesRegex(ValueError, '格式'):
                verify_paths(*paths)
            public.unlink()
            self.assertEqual(suggested_paths(str(original))[1], '')
            with self.assertRaisesRegex(ValueError, '不存在'):
                verify_paths(*paths)
