"""Validated file verification inputs with actionable Chinese errors."""
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from token_tool import file_digest


def suggested_paths(filename):
    """Return existing companion paths, leaving missing ones empty."""
    return tuple(str(Path(filename + suffix)) if Path(filename + suffix).is_file() else ''
                 for suffix in ('.sig', '.public.pem'))


def verify_paths(filename, signature, public_path):
    """Validate selected files and verify the detached RSA signature."""
    for label, value in [('原文件', filename), ('签名文件 .sig', signature), ('公钥文件 .pem', public_path)]:
        if not value.strip():
            raise ValueError(f'尚未选择{label}，请点击该行的“浏览…”。')
        if not Path(value).is_file():
            raise ValueError(f'{label}不存在或不是文件：\n{value}')
    if len({Path(value).resolve() for value in (filename, signature, public_path)}) != 3:
        raise ValueError('三个输入必须是不同文件：原文件、.sig 签名和 .pem 公钥。')
    try:
        public = serialization.load_pem_public_key(Path(public_path).read_bytes())
    except (ValueError, TypeError) as error:
        raise ValueError('公钥文件格式不正确，请选择签名时生成的 .public.pem 文件。') from error
    if not isinstance(public, rsa.RSAPublicKey):
        raise ValueError('请选择 RSA 公钥文件。')
    signed = Path(signature).read_bytes()
    if len(signed) != (public.key_size + 7) // 8:
        raise ValueError('签名文件长度不正确，请确认选择的是对应的 .sig 文件。')
    try:
        public.verify(signed, file_digest(filename), padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
    except InvalidSignature as error:
        raise ValueError('文件、签名和公钥不匹配。文件可能被修改，或选择了其他文件的签名／公钥。') from error
