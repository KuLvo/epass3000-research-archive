"""Interactive Windows VT console connected to an authenticated SSH PTY."""
import argparse
import contextlib
import ctypes
from ctypes import wintypes
import getpass
import os
from pathlib import Path
import shutil
import socket
import sys
import threading

import paramiko
from ssh_support import connect_token, validate_connection
from token_tool import Token


class WindowsConsole:
    """Enable raw UTF-8 VT input/output and restore all console settings."""

    def __init__(self):
        self.api = ctypes.WinDLL('kernel32', use_last_error=True)
        self.api.GetStdHandle.argtypes = [wintypes.DWORD]
        self.api.GetStdHandle.restype = wintypes.HANDLE
        self.api.GetConsoleMode.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        self.api.SetConsoleMode.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        self.input = self.api.GetStdHandle(-10 & 0xffffffff)
        self.output = self.api.GetStdHandle(-11 & 0xffffffff)
        self.saved = []
        self.codepages = None
        self.file_modes = []

    def __enter__(self):
        try:
            for handle in (self.input, self.output):
                mode = wintypes.DWORD()
                if not self.api.GetConsoleMode(handle, ctypes.byref(mode)):
                    raise OSError('请从图形界面的“打开完整终端”启动，需使用真实 Windows 控制台。')
                self.saved.append((handle, mode.value))
            # Raw VT input: disable processed input, line input, echo and Quick Edit.
            incoming = (self.saved[0][1] | 0x200 | 0x80) & ~(0x01 | 0x02 | 0x04 | 0x40)
            outgoing = self.saved[1][1] | 0x01 | 0x04
            for handle, mode in ((self.input, incoming), (self.output, outgoing)):
                if not self.api.SetConsoleMode(handle, mode):
                    raise OSError('Windows 控制台不支持 VT，请使用 Windows 10/11 控制台。')
            self.codepages = (self.api.GetConsoleCP(), self.api.GetConsoleOutputCP())
            self.api.SetConsoleCP(65001)
            self.api.SetConsoleOutputCP(65001)
            import msvcrt
            for stream in (sys.stdin, sys.stdout):
                descriptor = stream.fileno()
                self.file_modes.append((descriptor, msvcrt.setmode(descriptor, os.O_BINARY)))
            return self
        except Exception:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *_):
        import msvcrt
        for descriptor, mode in self.file_modes:
            msvcrt.setmode(descriptor, mode)
        for handle, mode in self.saved:
            self.api.SetConsoleMode(handle, mode)
        if self.codepages:
            self.api.SetConsoleCP(self.codepages[0])
            self.api.SetConsoleOutputCP(self.codepages[1])


def relay(channel, read_input, write_output, dimensions):
    """Relay bytes unchanged, resize the PTY, and stop on remote EOF."""
    stopped = threading.Event()
    failures = []

    def send_input():
        try:
            while not stopped.is_set():
                data = read_input()
                if not data:
                    channel.shutdown_write()
                    return
                channel.sendall(data)
        except (OSError, EOFError) as error:
            if not stopped.is_set():
                failures.append(error)
                channel.close()

    worker = threading.Thread(target=send_input, daemon=True)
    channel.settimeout(0.2)
    worker.start()
    previous = dimensions()
    try:
        while True:
            current = dimensions()
            if current != previous:
                channel.resize_pty(width=current[0], height=current[1])
                previous = current
            try:
                data = channel.recv(32768)
            except socket.timeout:
                continue
            if not data:
                break
            write_output(data)
        if failures:
            raise failures[0]
    finally:
        stopped.set()
        channel.close()


def trusted_host(path, host, port):
    """Require an already-approved server key before prompting for a PIN."""
    known = paramiko.HostKeys()
    if Path(path).exists():
        known.load(str(path))
    name = host if port == 22 else f'[{host}]:{port}'
    keys = known.lookup(name)
    if not keys:
        raise ValueError('尚未确认服务器指纹，请先在 SSH 窗口点击连接并核对指纹。')
    return next(iter(keys.values()))


def main():
    """Authenticate in the console and open a full SSH shell."""
    parser = argparse.ArgumentParser()
    parser.add_argument('host')
    parser.add_argument('port')
    parser.add_argument('user')
    args = parser.parse_args()
    host, port, user = validate_connection(args.host, args.port, args.user)
    base = Path(__file__).parent
    expected = trusted_host(base / 'ssh_known_hosts', host, port)
    print(f'USB Key SSH 终端：{user}@{host}:{port}\n输入 exit 退出；支持 Ctrl+C、方向键及交互式程序。')
    pin = getpass.getpass('USB Key PIN（不保存）: ')
    token = Token(base / 'libusb-1.0.dll')
    try:
        token.exchange(1)
        token.login(pin)
        client = connect_token(host, port, user, expected, token)
    finally:
        pin = None
        token.close()
    with contextlib.closing(client):
        size = shutil.get_terminal_size((100, 30))
        with contextlib.closing(client.invoke_shell(term='xterm-256color', width=size.columns, height=size.lines)) as channel:
            sys.stdout.flush()
            with WindowsConsole():
                relay(channel, lambda: os.read(sys.stdin.fileno(), 1024),
                      lambda data: write_bytes(sys.stdout.fileno(), data),
                      lambda: tuple(shutil.get_terminal_size((100, 30))))


def write_bytes(descriptor, data):
    """Write all bytes even if the console reports a partial write."""
    while data:
        written = os.write(descriptor, data)
        if written <= 0:
            raise OSError('控制台输出失败')
        data = data[written:]


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(f'\n连接失败：{error}')
        input('按回车关闭…')
        sys.exit(1)
