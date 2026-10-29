"""File signatures and SSH authentication with an existing ePass3000 key."""

import argparse
import base64
import ctypes as c
import getpass
import hashlib
from pathlib import Path
import struct
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
import paramiko


def parse_public(data):
    """Decode the token's exponent/modulus TLVs."""
    values = {}
    offset = 0
    while offset < len(data):
        if offset + 2 > len(data):
            raise ValueError('Truncated public key')
        tag = data[offset]
        size = data[offset + 1]
        offset += 2
        if size == 0x82:
            if offset + 2 > len(data):
                raise ValueError('Truncated TLV length')
            size = int.from_bytes(data[offset:offset + 2], 'big')
            offset += 2
        if size == 0 or offset + size > len(data) or tag in values:
            raise ValueError('Invalid public key TLV')
        values[tag] = int.from_bytes(data[offset:offset + size], 'little')
        offset += size
    key = rsa.RSAPublicNumbers(values[0x45], values[0x4e]).public_key()
    if key.key_size != 2048:
        raise ValueError('Expected RSA2048')
    return key


def encoded_digest(digest):
    """Construct the RSA PKCS#1 v1.5 SHA-256 encoded message."""
    if len(digest) != 32:
        raise ValueError('Expected SHA-256 digest')
    tail = bytes.fromhex('3031300d060960864801650304020105000420') + digest
    return b'\x00\x01' + b'\xff' * (256 - len(tail) - 3) + b'\x00' + tail


def file_digest(path):
    """Hash a file without loading it into memory."""
    with open(path, 'rb') as source:
        return hashlib.file_digest(source, 'sha256').digest()


class Token:
    """A non-destructive libusb transport; contains no key generation commands."""

    def __init__(self, dll):
        self.lib = c.CDLL(str(Path(dll).resolve()))
        self.ctx = c.c_void_p()
        self.dev = None
        self.lib.libusb_init.argtypes = [c.POINTER(c.c_void_p)]
        self.lib.libusb_open_device_with_vid_pid.argtypes = [c.c_void_p, c.c_uint16, c.c_uint16]
        self.lib.libusb_open_device_with_vid_pid.restype = c.c_void_p
        self.lib.libusb_claim_interface.argtypes = [c.c_void_p, c.c_int]
        self.lib.libusb_release_interface.argtypes = [c.c_void_p, c.c_int]
        self.lib.libusb_close.argtypes = [c.c_void_p]
        self.lib.libusb_exit.argtypes = [c.c_void_p]
        self.lib.libusb_bulk_transfer.argtypes = [c.c_void_p, c.c_ubyte, c.c_void_p, c.c_int, c.POINTER(c.c_int), c.c_uint]
        if self.lib.libusb_init(c.byref(self.ctx)) != 0:
            raise RuntimeError('libusb initialization failed')
        self.dev = self.lib.libusb_open_device_with_vid_pid(self.ctx, 0x096e, 0x0401)
        if not self.dev:
            self.close()
            raise RuntimeError('Token not found; close the manager and check WinUSB')
        if self.lib.libusb_claim_interface(self.dev, 0) != 0:
            self.close()
            raise RuntimeError('Cannot claim token; close other token programs')

    def close(self):
        """Release the USB handle and context."""
        if self.dev:
            self.lib.libusb_release_interface(self.dev, 0)
            self.lib.libusb_close(self.dev)
            self.dev = None
        if self.ctx:
            self.lib.libusb_exit(self.ctx)
            self.ctx = c.c_void_p()

    def exchange(self, command, data=b''):
        """Exchange a framed R6 command, rejecting transport errors."""
        packet = b'R6' + struct.pack('>HH', command, len(data)) + data
        sent = c.c_int()
        rc = self.lib.libusb_bulk_transfer(self.dev, 2, packet, len(packet), c.byref(sent), 5000)
        if rc or sent.value != len(packet):
            raise RuntimeError(f'USB write failed: {rc}')
        response = bytearray()
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            buf = c.create_string_buffer(64)
            count = c.c_int()
            rc = self.lib.libusb_bulk_transfer(self.dev, 0x81, buf, 64, c.byref(count), 2000)
            if rc:
                raise RuntimeError(f'USB read failed: {rc}')
            response.extend(buf.raw[:count.value])
            if len(response) >= 6:
                status, size = struct.unpack('>HH', response[2:6])
                if response[:2] != b'R6' or status:
                    raise RuntimeError('Invalid R6 response')
                if len(response) >= size + 6:
                    return bytes(response[6:6 + size])
        raise TimeoutError('Incomplete token response')

    def apdu(self, data):
        """Exchange APDUs and check every status, including GET RESPONSE."""
        result = bytearray()
        for _ in range(16):
            response = self.exchange(2, data)
            if len(response) < 2:
                raise RuntimeError('Missing APDU status')
            result.extend(response[:-2])
            if response[-2] == 0x61:
                data = bytes([0, 0xc0, 0, 0, response[-1]])
                continue
            if response[-2:] != b'\x90\x00':
                raise RuntimeError(f'Card returned {response[-2:].hex()}; no automatic retry')
            return bytes(result)
        raise RuntimeError('Too many GET RESPONSE operations')

    def public_key(self):
        """Read existing slot 1 without changing key material."""
        return parse_public(self.apdu(bytes.fromhex('80e62a0100')))

    def login(self, pin):
        """Verify an explicitly supplied PIN exactly once."""
        encoded = pin.encode('utf-8')
        if not 1 <= len(encoded) <= 16:
            raise ValueError('PIN must contain 1 to 16 UTF-8 bytes')
        self.apdu(bytes.fromhex('0020000110') + encoded.ljust(16, b'\x00'))

    def sign_digest(self, digest):
        """Sign SHA-256 using on-card raw RSA and verify before returning."""
        public = self.public_key()
        block = encoded_digest(digest)
        mse = bytes.fromhex('800180830201228940') + block[:64]
        self.apdu(bytes.fromhex('002241b8') + bytes([len(mse)]) + mse)
        signature = self.apdu(bytes.fromhex('002a8680c0') + block[64:])
        public.verify(signature, digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
        return signature


class TokenSSHKey(paramiko.PKey):
    """Paramiko RSA key backed exclusively by slot 1."""

    def __init__(self, token):
        self.token = token
        self.public = token.public_key()
        self.public_blob = None

    def get_name(self):
        return 'ssh-rsa'

    def asbytes(self):
        encoded = self.public.public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        return base64.b64decode(encoded.split()[1])

    def get_bits(self):
        return self.public.key_size

    def can_sign(self):
        return True

    def sign_ssh_data(self, data, algorithm=None):
        if algorithm != 'rsa-sha2-256':
            raise ValueError('Only rsa-sha2-256 is enabled')
        message = paramiko.Message()
        message.add_string(algorithm)
        message.add_string(self.token.sign_digest(hashlib.sha256(data).digest()))
        return message


def main():
    """Command line entry point; PIN is never accepted on the command line."""
    parser = argparse.ArgumentParser(description='ePass3000 file signatures / SSH')
    parser.add_argument('--dll', default=str(Path(__file__).parent / 'libusb-1.0.dll'))
    sub = parser.add_subparsers(dest='action', required=True)
    sub.add_parser('public')
    sub.add_parser('selftest')
    sign = sub.add_parser('sign')
    sign.add_argument('file')
    verify = sub.add_parser('verify')
    verify.add_argument('file')
    verify.add_argument('signature')
    verify.add_argument('public_key')
    ssh = sub.add_parser('ssh')
    ssh.add_argument('host')
    ssh.add_argument('user')
    ssh.add_argument('--port', type=int, default=22)
    ssh.add_argument('--known-hosts', required=True)
    args = parser.parse_args()
    if args.action == 'verify':
        public = serialization.load_pem_public_key(Path(args.public_key).read_bytes())
        public.verify(Path(args.signature).read_bytes(), file_digest(args.file), padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
        print('验签通过')
        return
    token = Token(args.dll)
    try:
        token.exchange(1)
        public = token.public_key()
        if args.action == 'public':
            print(public.public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode())
            return
        token.login(getpass.getpass('USB Key PIN: '))
        if args.action == 'selftest':
            run_selftest(token)
        elif args.action == 'sign':
            signature = token.sign_digest(file_digest(args.file))
            with open(args.file + '.sig', 'xb') as output:
                output.write(signature)
            with open(args.file + '.public.pem', 'xb') as output:
                output.write(public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
            print('签名及独立验签通过；公钥须通过可信渠道确认。')
        else:
            with paramiko.SSHClient() as client:
                client.load_host_keys(args.known_hosts)
                client.set_missing_host_key_policy(paramiko.RejectPolicy())
                client.connect(args.host, port=args.port, username=args.user, pkey=TokenSSHKey(token), allow_agent=False, look_for_keys=False, timeout=15, disabled_algorithms={'pubkeys': ['ssh-rsa', 'rsa-sha2-512']})
                print('SSH 公钥认证成功')
    finally:
        token.close()


def run_selftest(token):
    """Test on-card signatures and SSH wire-format verification locally."""
    from cryptography.exceptions import InvalidSignature
    public = token.public_key()
    digest = hashlib.sha256(b'ePass3000 file signature test').digest()
    signature = token.sign_digest(digest)
    public.verify(signature, digest, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
    try:
        public.verify(signature, hashlib.sha256(b'tampered file').digest(), padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
    except InvalidSignature:
        print('文件签名：通过；篡改文件：正确拒绝')
    else:
        raise AssertionError('Tampered file accepted')
    key = TokenSSHKey(token)
    verifier = paramiko.RSAKey(data=key.asbytes())
    challenge = b'ePass3000 local SSH authentication challenge'
    wire = key.sign_ssh_data(challenge, 'rsa-sha2-256').asbytes()
    if not verifier.verify_ssh_sig(challenge, paramiko.Message(wire)):
        raise AssertionError('SSH signature rejected')
    if verifier.verify_ssh_sig(challenge + b'changed', paramiko.Message(wire)):
        raise AssertionError('Altered SSH challenge accepted')
    print('SSH rsa-sha2-256 签名：通过；篡改认证数据：正确拒绝（未连接服务器）')


if __name__ == '__main__':
    main()
