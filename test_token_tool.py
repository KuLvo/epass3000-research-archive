"""Offline protocol and cryptographic negative tests."""
import hashlib
import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
import paramiko

from token_tool import Token, TokenSSHKey, encoded_digest, parse_public


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public = self.private.public_key()

    def test_public_tlv(self):
        numbers = self.public.public_numbers()
        wire = b'\x45\x04' + numbers.e.to_bytes(4, 'little')
        wire += b'\x4e\x82\x01\x00' + numbers.n.to_bytes(256, 'little')
        self.assertEqual(parse_public(wire).public_numbers(), numbers)
        with self.assertRaises(ValueError):
            parse_public(wire[:-1])

    def test_encoding_and_tamper(self):
        digest = hashlib.sha256(b'file').digest()
        block = encoded_digest(digest)
        numbers = self.private.private_numbers()
        signature = pow(int.from_bytes(block, 'big'), numbers.d, numbers.public_numbers.n).to_bytes(256, 'big')
        self.public.verify(signature, digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
        with self.assertRaises(InvalidSignature):
            self.public.verify(signature, hashlib.sha256(b'changed').digest(), padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
        with self.assertRaises(ValueError):
            encoded_digest(b'short')

    def test_ssh_wire_format(self):
        private = self.private
        public = self.public

        class FakeToken:
            def public_key(self):
                return public

            def sign_digest(self, digest):
                return private.sign(digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))

        key = TokenSSHKey(FakeToken())
        verifier = paramiko.RSAKey(data=key.asbytes())
        wire = key.sign_ssh_data(b'challenge', 'rsa-sha2-256').asbytes()
        self.assertTrue(verifier.verify_ssh_sig(b'challenge', paramiko.Message(wire)))
        self.assertFalse(verifier.verify_ssh_sig(b'changed', paramiko.Message(wire)))
        with self.assertRaises(ValueError):
            key.sign_ssh_data(b'challenge', 'ssh-rsa')

    def test_status_rejected(self):
        token = object.__new__(Token)
        token.exchange = lambda *_: bytes.fromhex('6982')
        with self.assertRaises(RuntimeError):
            token.apdu(b'test')

    def test_get_response(self):
        token = object.__new__(Token)
        replies = iter([b'first\x61\x04', b'last\x90\x00'])
        token.exchange = lambda *_: next(replies)
        self.assertEqual(token.apdu(b'test'), b'firstlast')


if __name__ == '__main__':
    unittest.main()
