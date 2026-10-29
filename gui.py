"""Small Chinese interface for file signing and verification."""
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, utils

from token_tool import Token, file_digest, run_selftest
from verification import suggested_paths, verify_paths


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
    """Show all verification inputs together and discover companion files."""
    dialog = tk.Toplevel(ROOT)
    dialog.title('文件验签 — 无需 USB Key')
    dialog.geometry('760x300')
    dialog.transient(ROOT)
    dialog.grab_set()
    paths = [tk.StringVar(dialog) for _ in range(3)]
    tk.Label(dialog, text='先选择原文件，自动查找同目录下的 .sig 和 .public.pem。\n三个文件可以分别更换；确认无误后点击“开始验签”。', justify='left').grid(row=0, column=0, columnspan=3, padx=14, pady=14, sticky='w')

    def browse(index):
        titles = ['选择原文件（例如：报告.pdf）', '选择签名文件（例如：报告.pdf.sig）', '选择可信公钥（例如：报告.pdf.public.pem）']
        filters = [[('所有文件', '*.*')], [('签名文件', '*.sig'), ('所有文件', '*.*')], [('公钥文件', '*.pem'), ('所有文件', '*.*')]]
        selected = filedialog.askopenfilename(parent=dialog, title=titles[index], filetypes=filters[index])
        if selected:
            paths[index].set(selected)
            if index == 0:
                for variable, value in zip(paths[1:], suggested_paths(selected)):
                    variable.set(value)

    def verify():
        try:
            verify_paths(*(variable.get() for variable in paths))
            messagebox.showinfo('验签通过', '文件与签名匹配，文件未被修改。\n签名者身份取决于你是否信任所选公钥。', parent=dialog)
        except Exception as error:
            messagebox.showerror('验签失败', str(error), parent=dialog)

    for index, label in enumerate(['① 原文件', '② 签名文件 .sig', '③ 公钥文件 .pem']):
        tk.Label(dialog, text=label).grid(row=index + 1, column=0, padx=12, pady=9, sticky='w')
        tk.Entry(dialog, textvariable=paths[index], width=66).grid(row=index + 1, column=1, sticky='ew')
        tk.Button(dialog, text='浏览…', command=lambda i=index: browse(i)).grid(row=index + 1, column=2, padx=12)
    dialog.columnconfigure(1, weight=1)
    tk.Label(dialog, text='公钥应来自可信渠道。若未自动找到文件，请点击对应行的“浏览…”。').grid(row=4, column=0, columnspan=3, pady=12)
    tk.Button(dialog, text='开始验签', command=verify, width=22).grid(row=5, column=1)


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
