#!/usr/bin/env python3
"""Generate RSA keys and encrypt/decrypt text with RSA-OAEP + AES-GCM."""

import base64
import getpass
import importlib
import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import tkinter as tk
from tkinter import filedialog

class InvalidTag(Exception):
    pass


class UnsupportedAlgorithm(Exception):
    pass


def load_crypto_modules():
    global InvalidTag, UnsupportedAlgorithm, hashes, serialization, padding, rsa, AESGCM

    from cryptography.exceptions import InvalidTag, UnsupportedAlgorithm
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM


try:
    load_crypto_modules()
except ImportError as exc:
    _CRYPTO_IMPORT_ERROR = exc
else:
    _CRYPTO_IMPORT_ERROR = None


def ensure_crypto_modules():
    global _CRYPTO_IMPORT_ERROR
    if _CRYPTO_IMPORT_ERROR is None:
        return True

    print(f"当前 Python {sys.version.split()[0]} 环境缺少 cryptography。")
    print("安装程序会根据当前 Python 版本选择兼容版本，不固定依赖版本。")
    try:
        choice = input("是否现在尝试安装？[Y/n]: ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        print("\n已取消安装。")
        return False
    if choice not in ("", "y", "yes"):
        print(f'需要时可运行："{sys.executable}" -m pip install cryptography')
        return False

    command = [sys.executable, "-m", "pip", "install", "--only-binary=:all:"]
    if sys.prefix == sys.base_prefix:
        command.append("--user")
    command.append("cryptography")
    print(f"正在为当前 Python 安装兼容版本：{sys.executable}")
    result = subprocess.run(command, check=False)
    if result.returncode != 0:
        print("安装失败。请检查网络连接和 pip，然后运行上面显示的安装命令。")
        return False

    importlib.invalidate_caches()
    try:
        load_crypto_modules()
    except ImportError as exc:
        _CRYPTO_IMPORT_ERROR = exc
        print(f"安装后仍无法加载 cryptography：{exc}")
        print("请确认使用同一个 Python 解释器重新运行此脚本。")
        return False

    _CRYPTO_IMPORT_ERROR = None
    print("依赖安装成功。")
    return True


def ensure_openssh_encryption():
    try:
        import bcrypt

        return True
    except ImportError:
        pass

    print("加密 OpenSSH 私钥需要 bcrypt 支持。")
    try:
        choice = input("是否为当前 Python 安装 bcrypt？[Y/n]: ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        print("\n已取消安装。")
        return False
    if choice not in ("", "y", "yes"):
        return False

    command = [sys.executable, "-m", "pip", "install", "--only-binary=:all:"]
    if sys.prefix == sys.base_prefix:
        command.append("--user")
    command.append("bcrypt")
    result = subprocess.run(command, check=False)
    if result.returncode != 0:
        print("bcrypt 安装失败；未生成未加密的 OpenSSH 私钥。")
        return False
    importlib.invalidate_caches()
    try:
        import bcrypt
    except ImportError as exc:
        raise RuntimeError(f"bcrypt 安装后仍无法加载：{exc}") from exc
    return True


def create_dialog_root():
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    return root


def clean_path(value):
    return Path(value.strip().strip('"').strip("'")).expanduser()


def is_browse_request(value):
    return not value or value in ("?", "？")


def choose_format(prompt, options):
    print(prompt)
    for number, (label, _) in enumerate(options, 1):
        print(f"{number}. {label}")
    while True:
        choice = input("请选择格式: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(options):
            return options[int(choice) - 1][1]
        print(f"请输入 1 到 {len(options)}。")


def ask_existing_file(label, filetypes):
    value = input(f"{label}（粘贴路径；直接回车、? 或？可浏览选择）: ").strip()
    if is_browse_request(value):
        root = create_dialog_root()
        try:
            selected = filedialog.askopenfilename(title=label, filetypes=filetypes)
        finally:
            root.destroy()
        if not selected:
            raise ValueError("已取消文件选择。")
        path = Path(selected)
    else:
        path = clean_path(value)
    if not path.is_file():
        raise FileNotFoundError(f"找不到文件：{path}")
    return path


def ask_output_file(default_name, title, filetypes):
    value = input("输出文件路径（粘贴路径；直接回车、? 或？可选择保存位置）: ").strip()
    if not is_browse_request(value):
        path = clean_path(value)
        if path.exists() and input(f"文件已存在，覆盖吗？{path} [y/N]: ").strip().lower() != "y":
            raise ValueError("已取消，未覆盖现有文件。")
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    root = create_dialog_root()
    try:
        selected = filedialog.asksaveasfilename(
            title=title,
            initialdir=str(Path.cwd()),
            initialfile=default_name,
            defaultextension=Path(default_name).suffix,
            filetypes=filetypes,
        )
    finally:
        root.destroy()
    if not selected:
        raise ValueError("已取消保存。")
    return Path(selected)


def choose_key_directory():
    value = input("密钥保存目录（直接回车=当前目录；粘贴目录路径；输入 ? 或？可浏览）: ").strip()
    if not value:
        return Path.cwd()
    if is_browse_request(value):
        root = create_dialog_root()
        try:
            selected = filedialog.askdirectory(title="选择密钥保存目录", initialdir=str(Path.cwd()))
        finally:
            root.destroy()
        if not selected:
            raise ValueError("已取消目录选择。")
        return Path(selected)
    return clean_path(value)


def generate_keys():
    directory = choose_key_directory()
    directory.mkdir(parents=True, exist_ok=True)
    key_format = choose_format(
        "选择 RSA 密钥格式：",
        [
            ("PEM (.pem，通用文本格式)", "pem"),
            ("DER (.der，二进制格式)", "der"),
            ("OpenSSH (.openssh / .pub)", "openssh"),
            ("ASCII 文本 (.asc，PEM 内容；不是 GPG/OpenPGP)", "asc"),
        ],
    )
    if key_format == "openssh" and not ensure_openssh_encryption():
        raise ValueError("未生成密钥。")
    private_suffix = ".openssh" if key_format == "openssh" else f".{key_format}"
    public_suffix = ".pub" if key_format == "openssh" else f".{key_format}"
    private_path = directory / f"private_key{private_suffix}"
    public_path = directory / f"public_key{public_suffix}"
    if private_path.exists() or public_path.exists():
        if input("目标目录已有同名密钥文件，覆盖吗？[y/N]: ").strip().lower() != "y":
            raise ValueError("已取消，未覆盖现有密钥。")

    password = getpass.getpass("设置私钥保护密码（必填）: ")
    if not password:
        raise ValueError("私钥保护密码不能为空。")
    if password != getpass.getpass("再次输入密码确认: "):
        raise ValueError("两次输入的密码不一致。")

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    if key_format == "openssh":
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8")),
        )
        public_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH,
        )
    else:
        encoding = serialization.Encoding.DER if key_format == "der" else serialization.Encoding.PEM
        private_bytes = private_key.private_bytes(
            encoding=encoding,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8")),
        )
        public_bytes = private_key.public_key().public_bytes(
            encoding=encoding,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    private_path.write_bytes(private_bytes)
    public_path.write_bytes(public_bytes)
    print(f"已生成密钥：\n  私钥：{private_path}\n  公钥：{public_path}")
    print("请妥善保管私钥和密码；不要把私钥发送给他人。")
    if key_format == "asc":
        print("注意：.asc 是此工具保存的 PEM 文本，不是 GPG/OpenPGP 密钥。")


def load_public_key(path):
    data = path.read_bytes()
    loaders = (
        serialization.load_ssh_public_key,
        serialization.load_pem_public_key,
        serialization.load_der_public_key,
    )
    key = None
    for loader in loaders:
        try:
            key = loader(data)
            break
        except (ValueError, TypeError, UnsupportedAlgorithm):
            continue
    if key is None:
        raise ValueError("无法识别公钥格式；支持 PEM、DER 和 OpenSSH RSA 公钥。")
    if not isinstance(key, rsa.RSAPublicKey):
        raise ValueError("所选文件不是 RSA 公钥。")
    return key


def load_private_key(path):
    password_text = getpass.getpass("请输入私钥保护密码（未加密的密钥可直接回车）: ")
    password = password_text.encode("utf-8") if password_text else None
    data = path.read_bytes()
    loaders = (
        serialization.load_pem_private_key,
        serialization.load_der_private_key,
        serialization.load_ssh_private_key,
    )
    key = None
    for loader in loaders:
        try:
            key = loader(data, password=password)
            break
        except (ValueError, TypeError, UnsupportedAlgorithm):
            continue
    if key is None:
        raise ValueError("无法识别私钥格式；支持 PEM、DER 和 OpenSSH RSA 私钥。")
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("所选文件不是 RSA 私钥。")
    return key


def encrypt_message():
    public_path = ask_existing_file(
        "选择 RSA 公钥",
        [
            ("PEM / ASC 公钥", "*.pem *.asc"),
            ("DER 公钥", "*.der"),
            ("OpenSSH 公钥", "*.pub"),
            ("所有文件", "*.*"),
        ],
    )
    public_key = load_public_key(public_path)
    message = input("输入要加密的文本: ")

    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = __import__("os").urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, message.encode("utf-8"), None)
    wrapped_key = public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    envelope = {
        "version": 1,
        "algorithm": "RSA-OAEP-SHA256+AES-256-GCM",
        "wrapped_key": base64.b64encode(wrapped_key).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }
    output_format = choose_format(
        "选择加密结果格式：",
        [
            ("JSON (.json)", "json"),
            ("ASCII 文本封装 (.asc；不是 GPG/OpenPGP)", "asc"),
        ],
    )
    if output_format == "json":
        default_name = "encrypted_message.json"
        filetypes = [("JSON 文件", "*.json"), ("所有文件", "*.*")]
        output_data = json.dumps(envelope, indent=2).encode("utf-8")
    else:
        default_name = "encrypted_message.asc"
        filetypes = [("ASCII 加密文件", "*.asc"), ("所有文件", "*.*")]
        payload = base64.b64encode(json.dumps(envelope, separators=(",", ":")).encode("utf-8")).decode("ascii")
        output_data = (
            "-----BEGIN SECURE MESSAGE-----\n"
            + "\n".join(textwrap.wrap(payload, 64))
            + "\n-----END SECURE MESSAGE-----\n"
        ).encode("ascii")
    output_path = ask_output_file(default_name, "保存加密信息", filetypes)
    if not output_path.suffix:
        output_path = output_path.with_suffix(Path(default_name).suffix)
    output_path.write_bytes(output_data)
    print(f"加密完成，文件已保存到：{output_path}")


def decrypt_message():
    private_path = ask_existing_file(
        "选择 RSA 私钥",
        [
            ("PEM / ASC 私钥", "*.pem *.asc *.openssh"),
            ("DER 私钥", "*.der"),
            ("所有文件", "*.*"),
        ],
    )
    private_key = load_private_key(private_path)
    encrypted_path = ask_existing_file(
        "选择加密信息文件",
        [("加密信息文件", "*.json *.asc"), ("所有文件", "*.*")],
    )
    encrypted_data = encrypted_path.read_bytes()
    if encrypted_data.lstrip().startswith(b"-----BEGIN SECURE MESSAGE-----"):
        lines = encrypted_data.decode("ascii").splitlines()
        if len(lines) < 3 or lines[0] != "-----BEGIN SECURE MESSAGE-----" or lines[-1] != "-----END SECURE MESSAGE-----":
            raise ValueError("ASCII 加密文件格式无效。")
        payload = base64.b64decode("".join(lines[1:-1]), validate=True)
        envelope = json.loads(payload.decode("utf-8"))
    else:
        envelope = json.loads(encrypted_data.decode("utf-8"))
    if envelope.get("version") != 1:
        raise ValueError("不支持的加密文件版本。")

    wrapped_key = base64.b64decode(envelope["wrapped_key"], validate=True)
    nonce = base64.b64decode(envelope["nonce"], validate=True)
    ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
    aes_key = private_key.decrypt(
        wrapped_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    plaintext = AESGCM(aes_key).decrypt(nonce, ciphertext, None).decode("utf-8")
    print("\n解密结果：")
    print(plaintext)


def main():
    print("=== 私钥/公钥文本加解密工具 ===")
    if not ensure_crypto_modules():
        return
    while True:
        print("\n1. 生成私钥和公钥\n2. 使用公钥加密文本\n3. 使用私钥解密文件\n0. 退出")
        try:
            choice = input("\u8bf7\u9009\u62e9\u529f\u80fd: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n\u5df2\u53d6\u6d88\uff0c\u9000\u51fa\u3002")
            return
        if choice == "0":
            return
        actions = {"1": generate_keys, "2": encrypt_message, "3": decrypt_message}
        action = actions.get(choice)
        if action is None:
            print("无效选项，请输入 0、1、2 或 3。")
            continue
        try:
            action()
        except KeyboardInterrupt:
            print("\n\u5df2\u4e2d\u65ad\u5f53\u524d\u64cd\u4f5c\uff0c\u8fd4\u56de\u4e3b\u83dc\u5355\u3002")
            try:
                input("\u6309\u56de\u8f66\u8fd4\u56de\u4e3b\u83dc\u5355...")
            except (KeyboardInterrupt, EOFError):
                pass
        except (FileNotFoundError, InvalidTag, ValueError, OSError, KeyError, json.JSONDecodeError) as exc:
            print(f"操作失败：{exc}")


def standard_python_executable():
    current = Path(sys.executable)
    candidates = (
        current.with_name("python.exe"),
        current.with_name(f"python{sys.version_info.major}.{sys.version_info.minor}.exe"),
    )
    for candidate in candidates:
        if not candidate.is_file() or candidate.resolve() == current.resolve():
            continue
        probe = subprocess.run(
            [
                str(candidate),
                "-c",
                "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor} "
                "{int(getattr(sys, \"_is_gil_enabled\", lambda: True)())}')",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        expected = f"{sys.version_info.major}.{sys.version_info.minor} 1"
        if probe.returncode == 0 and probe.stdout.strip() == expected:
            return candidate
    return None


def launch_console_if_needed():
    if os.name != "nt":
        return False

    executable_name = Path(sys.executable).name.casefold()
    needs_console = executable_name.startswith("pythonw")
    gil_enabled = getattr(sys, "_is_gil_enabled", lambda: True)()
    needs_standard_python = _CRYPTO_IMPORT_ERROR is not None and not gil_enabled
    if not needs_console and not needs_standard_python:
        return False

    if needs_standard_python:
        console_python = standard_python_executable()
    else:
        console_python = Path(sys.executable).with_name("python.exe")

    if console_python is None or not console_python.is_file():
        if needs_standard_python and not needs_console:
            print("当前是 free-threaded Python，cryptography 的构建依赖 cffi 不支持此环境。")
            print("请安装同一 Python 版本的标准（非 free-threaded）解释器后重新运行。")
            return False
        root = create_dialog_root()
        try:
            from tkinter import messagebox

            messagebox.showerror(
                "无法启动",
                "找不到可用的标准 Python 控制台解释器。请安装标准版 Python 后重新运行。",
            )
        finally:
            root.destroy()
        return True

    script_path = Path(__file__).resolve()
    print(f"正在切换到标准 Python：{console_python}")
    subprocess.Popen(
        [str(console_python), str(script_path), *sys.argv[1:]],
        cwd=str(script_path.parent),
        creationflags=subprocess.CREATE_NEW_CONSOLE if needs_console else 0,
    )
    return True


if __name__ == "__main__":
    if not launch_console_if_needed():
        try:
            main()
        except (KeyboardInterrupt, EOFError):
            print("\n已退出。")
        except Exception as exc:
            print(f"\n程序出错：{type(exc).__name__}: {exc}")
        try:
            input("\n程序已结束，按回车键关闭窗口...")
        except (EOFError, OSError):
            pass
