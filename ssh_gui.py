"""A guided SSH public-key authentication and command window."""
import json
from pathlib import Path
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, scrolledtext

import paramiko
from cryptography.hazmat.primitives import serialization
from token_tool import Token
from ssh_support import connect_token, fingerprint, probe_host, validate_connection


class SSHWindow:
    """Guide public-key installation, trusted host checking and login."""

    def __init__(self, parent):
        self.window = tk.Toplevel(parent)
        self.window.title('USB Key SSH 登录')
        self.window.geometry('820x660')
        self.base = Path(__file__).parent
        self.client = None
        self.busy = False
        self.events = queue.Queue()
        self.closed = False
        self.trust_path = self.base / 'ssh_known_hosts'
        self.settings_path = self.base / 'ssh_connection.json'
        self.host, self.port, self.user = [tk.StringVar(self.window, value=value) for value in ('', '22', '')]
        tk.Label(self.window, text='① 导出公钥交给服务器管理员 → ② 填写连接信息 → ③ 连接并输入 Key PIN', pady=12).pack()
        tk.Button(self.window, text='导出 / 复制我的 SSH 公钥', command=self.export_public).pack()
        form = tk.Frame(self.window)
        form.pack(fill='x', padx=15, pady=10)
        for row, (label, variable) in enumerate([('服务器 IP / 主机名', self.host), ('端口', self.port), ('用户名', self.user)]):
            tk.Label(form, text=label, width=20, anchor='w').grid(row=row, column=0, pady=4)
            tk.Entry(form, textvariable=variable, width=62).grid(row=row, column=1)
        buttons = tk.Frame(self.window)
        buttons.pack()
        tk.Button(buttons, text='连接（USB Key 认证）', command=self.connect).pack(side='left', padx=8)
        tk.Button(buttons, text='断开', command=self.disconnect).pack(side='left', padx=8)
        self.status = tk.StringVar(self.window, value='尚未连接；PIN 不会保存。')
        tk.Label(self.window, textvariable=self.status, wraplength=780).pack(pady=10)
        self.output = scrolledtext.ScrolledText(self.window, height=17, state='disabled')
        self.output.pack(fill='both', expand=True, padx=15)
        self.command = tk.StringVar(self.window)
        tk.Entry(self.window, textvariable=self.command).pack(fill='x', padx=15, pady=6)
        tk.Button(self.window, text='执行命令（例如 whoami；不支持交互式 sudo / vim）', command=self.execute).pack(pady=7)
        self.window.protocol('WM_DELETE_WINDOW', self.close)
        try:
            saved = json.loads(self.settings_path.read_text(encoding='utf-8'))
            for name, variable in [('host', self.host), ('port', self.port), ('user', self.user)]:
                variable.set(saved[name])
        except (OSError, ValueError, KeyError):
            pass
        self.window.after(100, self.poll)

    def run(self, task, success):
        """Run blocking work outside Tk and marshal results to its UI thread."""
        if self.busy:
            messagebox.showinfo('请稍候', '上一个操作尚未完成。', parent=self.window)
            return
        self.busy = True
        self.status.set('正在处理，请稍候…')

        def worker():
            try:
                self.events.put((success, task(), None))
            except Exception as error:
                self.events.put((success, None, error))

        threading.Thread(target=worker, daemon=True).start()

    def poll(self):
        """Deliver worker results without calling Tk from a worker thread."""
        if self.closed:
            return
        try:
            callback, result, error = self.events.get_nowait()
            self.busy = False
            if error:
                detail = str(error)
                if isinstance(error, paramiko.AuthenticationException):
                    detail = '服务器拒绝公钥。请确认用户名正确，并将导出的公钥加入该账户的 authorized_keys。'
                elif isinstance(error, paramiko.BadHostKeyException):
                    detail = '服务器主机密钥发生变化，已停止连接。请联系管理员核实。'
                self.status.set('操作失败')
                messagebox.showerror('SSH 操作失败', detail or type(error).__name__, parent=self.window)
            else:
                self.status.set('操作完成')
                callback(result)
        except queue.Empty:
            pass
        self.window.after(100, self.poll)

    def export_public(self):
        """Read the public key without asking for the private-key PIN."""
        def read():
            token = Token(self.base / 'libusb-1.0.dll')
            try:
                token.exchange(1)
                return token.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode() + ' epass3000\n'
            finally:
                token.close()

        def show(public):
            self.window.clipboard_clear()
            self.window.clipboard_append(public.strip())
            filename = filedialog.asksaveasfilename(parent=self.window, title='保存 SSH 公钥（内容也已复制）', initialfile='epass3000.pub', defaultextension='.pub')
            if filename:
                Path(filename).write_text(public, encoding='utf-8')
            self.write('公钥已复制。请让管理员将这一整行加入目标用户的 ~/.ssh/authorized_keys：\n' + public)

        self.run(read, show)

    def connect(self):
        """Probe host identity before requesting a PIN or authenticating."""
        if self.client:
            messagebox.showinfo('已连接', '请先断开现有连接。', parent=self.window)
            return
        try:
            target = validate_connection(self.host.get(), self.port.get(), self.user.get())
        except ValueError as error:
            messagebox.showerror('连接信息', str(error), parent=self.window)
            return
        self.run(lambda: probe_host(target[0], target[1]), lambda key: self.approve(target, key))

    def approve(self, target, key):
        """Require explicit first-use trust and reject changed server keys."""
        host, port, user = target
        name = host if port == 22 else f'[{host}]:{port}'
        known = paramiko.HostKeys()
        if self.trust_path.exists():
            known.load(str(self.trust_path))
        existing = known.lookup(name)
        if existing and not known.check(name, key):
            messagebox.showerror('主机密钥变化', '服务器密钥与之前确认的不一致，已停止。请联系管理员。', parent=self.window)
            return
        if not existing:
            if not messagebox.askyesno('首次连接：核对服务器身份', f'{host}:{port}\n{key.get_name()}\n{fingerprint(key)}\n\n请与服务器管理员提供的指纹核对。\n指纹一致并信任这台服务器吗？', parent=self.window):
                return
            known.add(name, key.get_name(), key)
            known.save(str(self.trust_path))
        pin = simpledialog.askstring('USB Key PIN', '输入 USB Key 用户 PIN（不是服务器密码）：', show='*', parent=self.window)
        if pin is None:
            return

        def login():
            token = Token(self.base / 'libusb-1.0.dll')
            try:
                token.exchange(1)
                token.login(pin)
                return connect_token(host, port, user, key, token)
            finally:
                token.close()

        def connected(client):
            self.client = client
            self.settings_path.write_text(json.dumps(dict(host=host, port=port, user=user), ensure_ascii=False), encoding='utf-8')
            self.status.set(f'已连接 {user}@{host}:{port}（USB Key 公钥认证）')
            self.write('认证成功。下方输入命令后点击执行。拔出 Key 不会自动断开已建立的 SSH 会话。\n')

        self.run(login, connected)

    def write(self, text):
        """Append plain output to the read-only transcript."""
        self.output.configure(state='normal')
        self.output.insert('end', text)
        self.output.see('end')
        self.output.configure(state='disabled')

    def execute(self):
        """Execute one bounded non-interactive remote command."""
        if not self.client or self.busy:
            return
        command = self.command.get().strip()
        if not command:
            return
        client = self.client
        self.write(f'\n$ {command}\n')

        def run_command():
            transport = client.get_transport()
            channel = transport.open_session(timeout=10)
            channel.settimeout(20)
            try:
                channel.set_combine_stderr(True)
                channel.exec_command(command)
                channel.shutdown_write()
                result = bytearray()
                while True:
                    chunk = channel.recv(4096)
                    if not chunk:
                        break
                    result.extend(chunk)
                    if len(result) > 1024 * 1024:
                        raise RuntimeError('输出超过 1 MiB，已停止本次命令。')
                return result.decode('utf-8', errors='replace')
            finally:
                channel.close()

        self.run(run_command, self.write)

    def disconnect(self):
        """Close the current session without modifying the server."""
        if self.busy:
            return
        if self.client:
            self.client.close()
            self.client = None
        self.status.set('已断开')

    def close(self):
        """Avoid abandoning an in-flight login and release the connection."""
        if self.busy:
            messagebox.showinfo('请稍候', '请等待当前操作结束后关闭。', parent=self.window)
            return
        self.disconnect()
        self.closed = True
        self.window.destroy()
