"""Small Chinese interface for file signing and verification."""
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, utils

from token_tool import Token, file_digest, run_selftest


def with_token(action):
    """Open the token for one explicitly requested operation."""
    pin = simpledialog.askstring('USB Key', '请输入用户 PIN（不保存）', show='*', parent=ROOT)
    if pin is None:
        return
    token = None
    try:
        token = Token(Path(__file__).parent / 'libusb-1.0.dll')
        token.exchange(1)
        token.login(pin)
        action(token)
    except Exception as error:
        messagebox.showerror('操作失败', str(error))
    finally:
        if token:
            token.close()


def sign_file():
    """Choose and sign a file; require fresh output paths."""
    filename = filedialog.askopenfilename(title='选择要签名的文件')
    if not filename:
        return
    if Path(filename + '.sig').exists() or Path(filename + '.public.pem').exists():
        messagebox.showerror('文件已存在', '签名或公钥文件已存在，请先移动旧文件。')
        return

    def sign(token):
        public = token.public_key()
        signature = token.sign_digest(file_digest(filename))
        with open(filename + '.sig', 'xb') as output:
            output.write(signature)
        with open(filename + '.public.pem', 'xb') as output:
            output.write(public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        messagebox.showinfo('完成', '签名及独立验签通过。\n已在原文件旁保存 .sig 和 .public.pem。')

    with_token(sign)


def verify_file():
    """Verify with a user-selected trusted public key, without a token."""
    filename = filedialog.askopenfilename(title='选择原文件')
    if not filename:
        return
    signature = filedialog.askopenfilename(title='选择签名 .sig')
    if not signature:
        return
    public_path = filedialog.askopenfilename(title='选择可信公钥 .pem')
    if not public_path:
        return
    try:
        public = serialization.load_pem_public_key(Path(public_path).read_bytes())
        public.verify(Path(signature).read_bytes(), file_digest(filename), padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
        messagebox.showinfo('验签', '验签通过')
    except Exception as error:
        messagebox.showerror('验签失败', str(error) or '文件、签名或公钥不匹配')


def selftest():
    """Run non-destructive file and SSH signing tests."""
    def test(token):
        run_selftest(token)
        messagebox.showinfo('通过', '文件签名与篡改检测通过。\nSSH SHA-256 签名与篡改检测通过。\n未连接服务器。')

    with_token(test)


if __name__ == '__main__':
    ROOT = tk.Tk()
    ROOT.title('ePass3000 文件签名与 SSH 测试')
    ROOT.geometry('500x290')
    tk.Label(ROOT, text='使用现有槽位 1；请先关闭其他密钥管理程序。', pady=15).pack()
    for label, command in [('文件签名', sign_file), ('文件验签（无需 USB Key）', verify_file), ('本地文件与 SSH 签名自检', selftest)]:
        tk.Button(ROOT, text=label, command=command, width=42, pady=8).pack(pady=5)
    tk.Label(ROOT, text='验签公钥请通过可信渠道确认；本工具不提供初始化或擦除。').pack(pady=10)
    ROOT.mainloop()
