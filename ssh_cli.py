"""Chinese SSH menu with password bootstrap and hardware-key login."""
import getpass
import json
from pathlib import Path
import stat
import subprocess
import sys

import paramiko
from cryptography.hazmat.primitives import serialization
from ssh_support import fingerprint, probe_host, validate_connection
from token_tool import Token

BASE = Path(__file__).parent
PROFILES = BASE / 'ssh_servers.json'
TRUST = BASE / 'ssh_known_hosts'


def load_profiles(path=PROFILES):
    """Load local profiles without storing passwords or PINs."""
    if not path.exists():
        return []
    profiles = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(profiles, list):
        raise ValueError('服务器配置格式错误')
    for profile in profiles:
        validate_connection(profile['host'], str(profile['port']), profile['user'])
    return profiles


def save_profiles(profiles, path=PROFILES):
    """Replace profile data atomically."""
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(profiles, ensure_ascii=False, indent=2), encoding='utf-8')
    temporary.replace(path)


def select_profile(profiles):
    """Select a numbered server; empty input cancels."""
    if not profiles:
        print('尚未添加服务器。')
        return None
    for index, profile in enumerate(profiles, 1):
        print(f"{index}. {profile['name']} — {profile['user']}@{profile['host']}:{profile['port']}")
    choice = input('输入编号（回车返回）：').strip()
    if not choice:
        return None
    if not choice.isdigit() or not 1 <= int(choice) <= len(profiles):
        raise ValueError('服务器编号无效')
    return int(choice) - 1


def approved_key(host, port):
    """Probe and explicitly approve first-use host identity."""
    key = probe_host(host, port)
    name = host if port == 22 else f'[{host}]:{port}'
    known = paramiko.HostKeys()
    if TRUST.exists():
        known.load(str(TRUST))
    existing = known.lookup(name)
    if existing and not known.check(name, key):
        raise ValueError('服务器主机密钥变化，已停止。请联系管理员核实。')
    if not existing:
        print(f'服务器指纹：{fingerprint(key)}')
        if input('请与管理员核对，一致后输入 yes：').strip().lower() != 'yes':
            raise ValueError('已取消服务器信任')
        known.add(name, key.get_name(), key)
        known.save(str(TRUST))
    return key


def append_public_key(sftp, public):
    """Append one key via SFTP, preserving existing keys and restrictions."""
    home = sftp.normalize('.')
    directory = home.rstrip('/') + '/.ssh'
    path = directory + '/authorized_keys'
    try:
        info = sftp.lstat(directory)
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError('.ssh 不是普通目录，停止写入')
    except FileNotFoundError:
        sftp.mkdir(directory, mode=0o700)
    sftp.chmod(directory, 0o700)
    existing = b''
    try:
        info = sftp.lstat(path)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError('authorized_keys 不是普通文件，停止写入')
        with sftp.open(path, 'rb') as source:
            existing = source.read()
    except FileNotFoundError:
        pass
    fields = public.strip().split()
    for line in existing.decode('utf-8', errors='replace').splitlines():
        parts = line.split()
        if any(parts[i:i + 2] == fields[:2] for i in range(len(parts) - 1)):
            return False
    suffix = (b'\n' if existing and not existing.endswith(b'\n') else b'')
    suffix += public.strip().encode('ascii') + b'\n'
    with sftp.open(path, 'ab') as destination:
        destination.write(suffix)
    sftp.chmod(path, 0o600)
    return True


def push_key(profile):
    """Use an entered server password to install the token's public key."""
    host, port, user = validate_connection(profile['host'], str(profile['port']), profile['user'])
    key = approved_key(host, port)
    token = Token(BASE / 'libusb-1.0.dll')
    try:
        token.exchange(1)
        public = token.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode() + ' epass3000'
    finally:
        token.close()
    password = getpass.getpass('服务器账户密码（不是 Key PIN，不保存）：')
    client = paramiko.SSHClient()
    name = host if port == 22 else f'[{host}]:{port}'
    client.get_host_keys().add(name, key.get_name(), key)
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect(host, port=port, username=user, password=password,
                       allow_agent=False, look_for_keys=False, timeout=10,
                       banner_timeout=10, auth_timeout=20)
        password = None
        with client.open_sftp() as sftp:
            added = append_public_key(sftp, public)
        print('公钥已追加到服务器。' if added else '服务器已有该公钥，保留原配置，不重复添加。')
    finally:
        password = None
        client.close()


def configure():
    """Manage local server records and explicitly requested key installation."""
    while True:
        print('\n配置服务器\n1. 添加服务器并推送公钥\n2. 给已有服务器推送公钥\n3. 删除本地服务器配置\n0. 返回')
        choice = input('请选择：').strip()
        if choice == '0':
            return
        profiles = load_profiles()
        if choice == '1':
            name = input('服务器名称：').strip()
            host = input('服务器 IP / 主机名：').strip()
            port = input('端口 [22]：').strip() or '22'
            user = input('用户名：').strip()
            host, port, user = validate_connection(host, port, user)
            profile = dict(name=name or host, host=host, port=port, user=user)
            profiles.append(profile)
            save_profiles(profiles)
            print('本地配置已保存；推送失败时可用菜单 2 重试。')
            push_key(profile)
        elif choice in ('2', '3'):
            selected = select_profile(profiles)
            if selected is None:
                continue
            if choice == '2':
                push_key(profiles[selected])
            elif input('只删除本地配置，保留服务器公钥。确认输入 yes：').strip().lower() == 'yes':
                profiles.pop(selected)
                save_profiles(profiles)
                print('本地配置已删除。')


def menu():
    """Run the interactive CLI and keep recoverable failures in the menu."""
    while True:
        print('\nUSB Key SSH\n1. 配置服务器\n2. 连接服务器\n0. 退出')
        try:
            choice = input('请选择：').strip()
            if choice == '0':
                return
            if choice == '1':
                configure()
            elif choice == '2':
                profiles = load_profiles()
                selected = select_profile(profiles)
                if selected is not None:
                    profile = profiles[selected]
                    approved_key(profile['host'], profile['port'])
                    subprocess.run([sys.executable, str(BASE / 'ssh_terminal.py'),
                                    profile['host'], str(profile['port']), profile['user']], check=False)
        except (EOFError, KeyboardInterrupt):
            print('\n已取消当前操作。')
            return
        except Exception as error:
            print(f'操作失败：{error}\n密码不会保存；如服务器禁用密码登录或 SFTP，请让管理员手动安装公钥。')


if __name__ == '__main__':
    menu()
