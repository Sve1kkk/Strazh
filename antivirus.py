# -*- coding: utf-8 -*-
"""
СТРАЖ — монитор процессов и антивирусный сканер.

Возможности:
  • все активные процессы в реальном времени: ЦП, ОЗУ, потоки, путь, пользователь;
  • запущенные программы (процессы, сгруппированные по программе);
  • автоматический поиск подозрительных процессов (эвристика);
  • автозагрузка (реестр Run/RunOnce, папки «Автозагрузка», LaunchAgents, autostart);
  • сканер файлов и папок: эвристика + Windows Defender / ClamAV + VirusTotal;
  • карантин с возможностью восстановления.

Запуск:  pip install psutil   →   python antivirus.py
На Windows лучше запускать от имени администратора — тогда видны пути всех процессов.
"""

import os
import re
import sys
import json
import time
import queue
import shutil
import hashlib
import getpass
import platform
import datetime
import threading
import subprocess
import urllib.request
import urllib.error
from pathlib import Path

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

def _auto_install_psutil():
    """Ставит psutil в тот же Python, которым запущена программа."""
    exe = sys.executable
    alt = os.path.join(os.path.dirname(exe), "python.exe")  # pythonw.exe → python.exe
    if exe.lower().endswith("pythonw.exe") and os.path.exists(alt):
        exe = alt
    flags = 0x08000000 if os.name == "nt" else 0
    r = subprocess.run([exe, "-m", "pip", "install", "--user", "psutil"],
                       capture_output=True, text=True, errors="replace", creationflags=flags)
    return r.returncode == 0, (r.stdout + r.stderr)[-1500:]


try:
    import psutil
except ImportError:
    _ok, _out = _auto_install_psutil()
    try:
        import site, importlib
        importlib.invalidate_caches()
        _us = site.getusersitepackages()
        if _us not in sys.path:
            sys.path.append(_us)
        import psutil
    except ImportError:
        _r = tk.Tk()
        _r.withdraw()
        messagebox.showerror(
            "Страж",
            "Не удалось установить библиотеку psutil.\n\n"
            f"Python: {sys.executable}\n\nОткройте командную строку и выполните:\n"
            f"\"{sys.executable}\" -m pip install psutil\n\nОшибка pip:\n{_out}",
        )
        sys.exit(1)


# ──────────────────────────────────────────────────────────────────────────────
#  Константы и настройки
# ──────────────────────────────────────────────────────────────────────────────

APP_NAME = "СТРАЖ"
APP_VERSION = "1.2.0"
UPDATE_REPO = "Sve1kkk/Strazh"   # GitHub-репозиторий, откуда приходят обновления
IS_WIN = os.name == "nt"
IS_MAC = sys.platform == "darwin"

DATA_DIR = Path.home() / ".strazh"
QUAR_DIR = DATA_DIR / "quarantine"
QUAR_INDEX = QUAR_DIR / "index.json"
CONFIG_FILE = DATA_DIR / "config.json"
LOG_FILE = DATA_DIR / "log.txt"
SHOW_FLAG = DATA_DIR / "show.flag"
UPDATE_DIR = DATA_DIR / "update"
SIG_FILE = DATA_DIR / "signatures.json"
TASK_NAME = "Strazh"
START_IN_TRAY = "--tray" in sys.argv
FROZEN = getattr(sys, "frozen", False)  # True, если запущен собранный Strazh.exe


def resource_path(name):
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, name)


ICON_FILE = resource_path("icon.ico")

WINDIR = os.path.normcase(os.environ.get("WINDIR", r"C:\Windows"))
NO_WINDOW = 0x08000000 if IS_WIN else 0  # CREATE_NO_WINDOW — без мигающей консоли

# Системные процессы Windows, которыми часто маскируются вирусы
SYSTEM_NAMES = {
    "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe",
    "smss.exe", "explorer.exe", "wininit.exe", "spoolsv.exe", "taskhostw.exe",
    "dwm.exe", "conhost.exe", "rundll32.exe", "lsm.exe", "taskmgr.exe",
    "dllhost.exe", "ctfmon.exe", "sihost.exe", "fontdrvhost.exe",
}

EXEC_EXT = {
    ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".vbs", ".vbe", ".js",
    ".jse", ".wsf", ".hta", ".ps1", ".msi", ".dll", ".jar", ".lnk", ".cpl",
    ".sh", ".app", ".command",
}
SCRIPT_EXT = {".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".ps1", ".sh", ".command"}
PE_OK_EXT = {".exe", ".dll", ".sys", ".scr", ".com", ".ocx", ".cpl", ".drv", ".efi", ".mui", ".msi", ".pyd", ".node"}

DOUBLE_EXT_RE = re.compile(
    r"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|mp3|mp4|avi|zip|rar|7z)\s*\.(exe|scr|com|pif|bat|cmd|vbs|js|hta|lnk)$",
    re.I,
)

SCRIPT_PATTERNS = [
    (rb"frombase64string", "Декодирует скрытый Base64-код"),
    (rb"-enc(odedcommand)?\s", "Запускает зашифрованную команду PowerShell"),
    (rb"invoke-expression|\biex\s*\(", "Выполняет код из строки (Invoke-Expression)"),
    (rb"downloadstring|downloadfile|invoke-webrequest|start-bitstransfer", "Скачивает файлы из интернета"),
    (rb"-w(indowstyle)?\s+hidden", "Запускается в скрытом окне"),
    (rb"wscript\.shell", "Управляет системой через WScript.Shell"),
    (rb"set-mppreference|disableantispyware|add-mppreference\s+-exclusionpath", "Пытается отключить антивирус"),
    (rb"vssadmin\s+delete\s+shadows|wbadmin\s+delete", "Удаляет резервные копии (признак шифровальщика)"),
    (rb"schtasks\s+/create", "Создаёт задание в планировщике"),
    (rb"reg\s+add\s+.*\\run", "Прописывается в автозагрузку"),
]

# SHA-256 известных образцов (тестовый файл EICAR — безопасный, нужен для проверки работы)
KNOWN_BAD = {
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR-Test-File (тестовый вирус)",
}

DEFAULT_CONFIG = {"vt_key": "", "interval": 2, "notify": True, "to_tray": True, "auto_update": True}


def ensure_dirs():
    QUAR_DIR.mkdir(parents=True, exist_ok=True)


def load_config():
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        return {**DEFAULT_CONFIG, **cfg}
    except Exception:
        return dict(DEFAULT_CONFIG)


def save_config(cfg):
    ensure_dirs()
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)


def log(text):
    try:
        ensure_dirs()
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{datetime.datetime.now():%Y-%m-%d %H:%M:%S}] {text}\n")
    except Exception:
        pass


def is_admin():
    try:
        if IS_WIN:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def temp_dirs():
    dirs = set()
    for v in ("TEMP", "TMP"):
        if os.environ.get(v):
            dirs.add(os.path.normcase(os.path.abspath(os.environ[v])))
    if IS_WIN:
        dirs.add(os.path.normcase(os.path.join(WINDIR, "temp")))
    else:
        dirs.update({"/tmp", "/var/tmp", "/dev/shm"})
    return dirs


TEMP_DIRS = temp_dirs()
DOWNLOADS = os.path.normcase(str(Path.home() / "Downloads"))
ROAMING = os.path.normcase(os.environ.get("APPDATA", "")) if IS_WIN else ""


def in_dir(path, folder):
    return bool(folder) and (path == folder or path.startswith(folder.rstrip("\\/") + os.sep))


# ──────────────────────────────────────────────────────────────────────────────
#  Эвристика
# ──────────────────────────────────────────────────────────────────────────────

def level_of(score):
    if score >= 50:
        return "danger"
    if score >= 20:
        return "warn"
    return "ok"


LEVEL_TEXT = {"danger": "ОПАСНО", "warn": "Подозрительно", "ok": "Норма"}


def analyze_process(name, exe, cpu_hist):
    """Возвращает (баллы, [причины]) для процесса."""
    score, reasons = 0, []
    n = (name or "").lower()
    if exe:
        e = os.path.normcase(exe)
        if IS_WIN and n in SYSTEM_NAMES and not e.startswith(WINDIR):
            score += 70
            reasons.append("Имя системного процесса, но запущен НЕ из папки Windows")
        if any(in_dir(e, t) for t in TEMP_DIRS):
            score += 40
            reasons.append("Запущен из временной папки (Temp)")
        if in_dir(e, DOWNLOADS):
            score += 15
            reasons.append("Запущен из папки «Загрузки»")
        if ROAMING and os.path.dirname(e) == ROAMING and e.endswith(".exe"):
            score += 30
            reasons.append("Программа лежит прямо в AppData\\Roaming (так прячутся трояны)")
        if DOUBLE_EXT_RE.search(e):
            score += 60
            reasons.append("Двойное расширение — маскируется под документ")
        if not os.path.exists(exe):
            score += 30
            reasons.append("Файл процесса удалён с диска, а процесс работает")
    if len(cpu_hist) >= 6 and min(cpu_hist[-6:]) > 70:
        score += 20
        reasons.append("Долго грузит процессор больше 70% (возможен майнер)")
    return score, reasons


def sha256_of(path, limit=300 * 1024 * 1024):
    try:
        if os.path.getsize(path) > limit:
            return None
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def analyze_file(path):
    """Эвристическая проверка файла. Возвращает (баллы, [причины], sha256)."""
    score, reasons = 0, []
    p = os.path.normcase(os.path.abspath(path))
    ext = os.path.splitext(p)[1].lower()
    name = os.path.basename(p)

    if DOUBLE_EXT_RE.search(name):
        score += 60
        reasons.append("Двойное расширение (например «фото.jpg.exe»)")
    if "\u202e" in name:
        score += 70
        reasons.append("В имени скрытый символ разворота текста (RLO)")
    if ext in EXEC_EXT and any(in_dir(p, t) for t in TEMP_DIRS):
        score += 25
        reasons.append("Исполняемый файл во временной папке")

    head = b""
    try:
        with open(path, "rb") as f:
            head = f.read(256 * 1024)
    except Exception as ex:
        reasons.append(f"Не удалось прочитать файл: {ex}")

    if head[:2] == b"MZ" and ext not in PE_OK_EXT:
        score += 60
        reasons.append("Это программа (.exe), замаскированная под другой тип файла")

    if ext in SCRIPT_EXT and head:
        low = head.lower()
        hits = 0
        for pat, why in SCRIPT_PATTERNS:
            if re.search(pat, low):
                hits += 1
                reasons.append("Скрипт: " + why)
        score += min(hits * 20, 70)

    digest = sha256_of(path)
    if digest and digest in KNOWN_BAD:
        score += 100
        reasons.append("Совпадает с известным вредоносным файлом: " + KNOWN_BAD[digest])
    return score, reasons, digest


# ──────────────────────────────────────────────────────────────────────────────
#  Внешние антивирусные движки
# ──────────────────────────────────────────────────────────────────────────────

def find_defender():
    if not IS_WIN:
        return None
    plat = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), "Microsoft", "Windows Defender", "Platform")
    try:
        for d in sorted(os.listdir(plat), reverse=True):
            c = os.path.join(plat, d, "MpCmdRun.exe")
            if os.path.exists(c):
                return c
    except Exception:
        pass
    c = os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "Windows Defender", "MpCmdRun.exe")
    return c if os.path.exists(c) else None


def find_clamav():
    return shutil.which("clamdscan") or shutil.which("clamscan")


def engine_name():
    if find_defender():
        return "Windows Defender"
    if find_clamav():
        return "ClamAV"
    return None


def run_cmd(cmd, timeout=1800):
    return subprocess.run(
        cmd, capture_output=True, text=True, errors="replace",
        timeout=timeout, creationflags=NO_WINDOW,
    )


def scan_with_engine(target):
    """
    Проверяет файл/папку встроенным антивирусом.
    Возвращает (ok, {путь: название_угрозы}, текст_ошибки).
    """
    found = {}
    mp = find_defender()
    if mp:
        try:
            r = run_cmd([mp, "-Scan", "-ScanType", "3", "-File", target, "-DisableRemediation"])
            threat = "угроза"
            for line in (r.stdout or "").splitlines():
                m = re.match(r"^\s*Threat\s*:\s*(.+)$", line)
                if m:
                    threat = m.group(1).strip()
                m = re.match(r"^\s*file\s*:\s*(.+?)(->.*)?$", line, re.I)
                if m:
                    found[os.path.normcase(m.group(1).strip())] = threat
            if r.returncode == 2 and not found:
                found[os.path.normcase(target)] = threat
            if r.returncode not in (0, 2):
                return False, found, (r.stdout or r.stderr or "").strip()[-300:]
            return True, found, ""
        except Exception as ex:
            return False, found, str(ex)

    clam = find_clamav()
    if clam:
        try:
            cmd = [clam, "--no-summary", "--infected"]
            if os.path.basename(clam).startswith("clamscan"):
                cmd.append("-r")
            r = run_cmd(cmd + [target])
            for line in (r.stdout or "").splitlines():
                m = re.match(r"^(.*): (.+) FOUND$", line)
                if m:
                    found[os.path.normcase(m.group(1))] = m.group(2)
            if r.returncode not in (0, 1):
                return False, found, (r.stderr or "").strip()[-300:]
            return True, found, ""
        except Exception as ex:
            return False, found, str(ex)
    return False, found, "Встроенный антивирус не найден"


def virustotal_lookup(digest, key):
    """Возвращает (статус, текст). Статус: danger / warn / ok / unknown / error."""
    if not key:
        return "error", "Нет API-ключа VirusTotal (вкладка «Настройки»)"
    req = urllib.request.Request(
        f"https://www.virustotal.com/api/v3/files/{digest}",
        headers={"x-apikey": key, "User-Agent": "Strazh/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        st = data["data"]["attributes"].get("last_analysis_stats", {})
        mal, sus = st.get("malicious", 0), st.get("suspicious", 0)
        total = sum(st.values()) or 1
        text = f"VirusTotal: {mal} из {total} антивирусов считают вредоносным"
        if mal >= 3:
            return "danger", text
        if mal or sus:
            return "warn", text
        return "ok", text
    except urllib.error.HTTPError as ex:
        if ex.code == 404:
            return "unknown", "VirusTotal: файл ещё никто не проверял"
        if ex.code == 401:
            return "error", "VirusTotal: неверный API-ключ"
        if ex.code == 429:
            return "error", "VirusTotal: превышен лимит запросов (4 в минуту)"
        return "error", f"VirusTotal: ошибка {ex.code}"
    except Exception as ex:
        return "error", f"VirusTotal недоступен: {ex}"


def signature_status(path):
    """Цифровая подпись файла (только Windows)."""
    if not IS_WIN:
        return None
    lit = path.replace("'", "''")
    try:
        r = run_cmd(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             f"(Get-AuthenticodeSignature -LiteralPath '{lit}').Status"],
            timeout=30,
        )
        s = (r.stdout or "").strip()
        return {"Valid": "Подписан (подпись в порядке)", "NotSigned": "НЕ подписан",
                "HashMismatch": "Подпись повреждена — файл изменён!",
                "UnknownError": "Подпись не проверена"}.get(s, s or "неизвестно")
    except Exception:
        return None


# ──────────────────────────────────────────────────────────────────────────────
#  Автозагрузка
# ──────────────────────────────────────────────────────────────────────────────

CMD_PATH_RE = re.compile(r'^\s*"([^"]+)"|^\s*(\S.*?\.(?:exe|bat|cmd|vbs|js|ps1|com|scr|lnk))\b', re.I)


def extract_path(cmd):
    cmd = os.path.expandvars(cmd or "")
    m = CMD_PATH_RE.match(cmd)
    if m:
        return m.group(1) or m.group(2)
    return cmd.split(" ")[0] if cmd else ""


def startup_entries():
    items = []
    if IS_WIN:
        try:
            import winreg
            keys = [
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU\\Run"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\RunOnce"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\RunOnce"),
                (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run (32-бит)"),
            ]
            for hive, sub, label in keys:
                try:
                    with winreg.OpenKey(hive, sub) as k:
                        i = 0
                        while True:
                            try:
                                name, val, _ = winreg.EnumValue(k, i)
                            except OSError:
                                break
                            items.append((name, str(val), "Реестр " + label))
                            i += 1
                except OSError:
                    pass
        except Exception:
            pass
        folders = [
            (os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup"), "Папка автозагрузки (пользователь)"),
            (os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"), r"Microsoft\Windows\Start Menu\Programs\StartUp"), "Папка автозагрузки (все)"),
        ]
    elif IS_MAC:
        folders = [
            (str(Path.home() / "Library/LaunchAgents"), "LaunchAgents (пользователь)"),
            ("/Library/LaunchAgents", "LaunchAgents (система)"),
            ("/Library/LaunchDaemons", "LaunchDaemons"),
        ]
    else:
        folders = [
            (str(Path.home() / ".config/autostart"), "autostart (пользователь)"),
            ("/etc/xdg/autostart", "autostart (система)"),
        ]
    for folder, label in folders:
        try:
            for fn in sorted(os.listdir(folder)):
                if fn.lower() == "desktop.ini":
                    continue
                items.append((fn, os.path.join(folder, fn), label))
        except Exception:
            pass
    return items


# ──────────────────────────────────────────────────────────────────────────────
#  Карантин
# ──────────────────────────────────────────────────────────────────────────────

def quar_load():
    try:
        with open(QUAR_INDEX, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def quar_save(items):
    ensure_dirs()
    with open(QUAR_INDEX, "w", encoding="utf-8") as f:
        json.dump(items, f, ensure_ascii=False, indent=2)


def quarantine_file(path, reason=""):
    ensure_dirs()
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    dst = QUAR_DIR / f"{ts}_{os.path.basename(path)}.quar"
    shutil.move(path, dst)
    items = quar_load()
    items.append({"file": dst.name, "original": path, "date": f"{datetime.datetime.now():%d.%m.%Y %H:%M}", "reason": reason})
    quar_save(items)
    log(f"В карантин: {path} ({reason})")


# ──────────────────────────────────────────────────────────────────────────────
#  Дубликаты файлов
# ──────────────────────────────────────────────────────────────────────────────

DUP_SKIP_DIRS = {"appdata", ".strazh", "node_modules", "$recycle.bin", ".git", "system volume information",
                 "windows", "program files", "program files (x86)", "programdata", "__pycache__", ".trash"}

_COPY_PATTERNS = [
    re.compile(r"\s*\(\d+\)$"),                                  # файл (1)
    re.compile(r"\s*\[\d+\]$"),                                  # файл [1]
    re.compile(r"\s*-\s*(копия|copy)(\s*\(\d+\))?$", re.I),       # файл - копия, файл - Copy (2)
    re.compile(r"\s+(копия|copy)(\s*\d+)?$", re.I),               # файл копия 2
    re.compile(r"^(копия|copy of)\s+", re.I),                     # Копия файл, Copy of файл
]


def norm_name(name, is_dir=False):
    base, ext = (name, "") if is_dir else os.path.splitext(name)
    prev = None
    while prev != base:
        prev = base
        for rx in _COPY_PATTERNS:
            base = rx.sub("", base).strip()
    return (base + ext).lower()


def dir_size(path):
    total = 0
    for root, _, files in os.walk(path):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
    return total


def _partial_hash(path, chunk=65536):
    h = hashlib.blake2b(digest_size=16)
    with open(path, "rb") as f:
        h.update(f.read(chunk))
        try:
            f.seek(-chunk, 2)
        except OSError:
            f.seek(0)
        h.update(f.read(chunk))
    return h.hexdigest()


def _full_hash(path):
    h = hashlib.blake2b(digest_size=20)
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def to_recycle_bin(path):
    """Удаляет файл/папку В КОРЗИНУ (можно восстановить). Возвращает True при успехе."""
    if IS_WIN:
        import ctypes
        from ctypes import wintypes

        class SHFILEOPSTRUCTW(ctypes.Structure):
            _fields_ = [("hwnd", wintypes.HWND), ("wFunc", wintypes.UINT), ("pFrom", ctypes.c_void_p),
                        ("pTo", ctypes.c_void_p), ("fFlags", ctypes.c_ushort), ("fAnyOperationsAborted", wintypes.BOOL),
                        ("hNameMappings", ctypes.c_void_p), ("lpszProgressTitle", ctypes.c_void_p)]

        buf = ctypes.create_unicode_buffer(os.path.abspath(path) + "\0\0")
        op = SHFILEOPSTRUCTW()
        op.wFunc = 3  # FO_DELETE
        op.pFrom = ctypes.addressof(buf)
        op.fFlags = 0x40 | 0x10 | 0x04 | 0x400  # ALLOWUNDO | NOCONFIRMATION | SILENT | NOERRORUI
        return ctypes.windll.shell32.SHFileOperationW(ctypes.byref(op)) == 0 and not os.path.exists(path)
    trash = Path.home() / (".Trash" if IS_MAC else ".local/share/Trash/files")
    trash.mkdir(parents=True, exist_ok=True)
    dst = trash / os.path.basename(path)
    if dst.exists():
        dst = trash / f"{time.time():.0f}_{os.path.basename(path)}"
    shutil.move(path, dst)
    return True


def open_in_explorer(path):
    try:
        if IS_WIN:
            if os.path.isfile(path):
                subprocess.Popen(["explorer", "/select,", os.path.normpath(path)])
            else:
                os.startfile(path if os.path.isdir(path) else os.path.dirname(path))
        elif IS_MAC:
            subprocess.Popen(["open", "-R", path])
        else:
            subprocess.Popen(["xdg-open", os.path.dirname(path) if os.path.isfile(path) else path])
    except Exception as ex:
        messagebox.showerror(APP_NAME, f"Не удалось открыть папку:\n{ex}")


# ──────────────────────────────────────────────────────────────────────────────
#  Обновления (программа + база угроз) с GitHub
# ──────────────────────────────────────────────────────────────────────────────

def http_get(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": f"Strazh/{APP_VERSION}",
                                               "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def ver_tuple(v):
    return tuple(int(x) for x in re.findall(r"\d+", v or "0")[:4])


def load_signatures():
    """Подгружает скачанную базу угроз в KNOWN_BAD."""
    try:
        with open(SIG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        for h, name in (data.get("sha256") or {}).items():
            if re.fullmatch(r"[0-9a-fA-F]{64}", h):
                KNOWN_BAD[h.lower()] = str(name)
        return data.get("version", "")
    except Exception:
        return ""


def update_signatures():
    """Скачивает signatures.json из репозитория. Возвращает число записей или None."""
    raw = http_get(f"https://raw.githubusercontent.com/{UPDATE_REPO}/main/signatures.json")
    data = json.loads(raw.decode("utf-8-sig"))
    if not isinstance(data.get("sha256"), dict):
        return None
    ensure_dirs()
    with open(SIG_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)
    load_signatures()
    return len(data["sha256"])


def check_update():
    """Ищет новую версию в GitHub Releases. Возвращает dict или None."""
    data = json.loads(http_get(f"https://api.github.com/repos/{UPDATE_REPO}/releases/latest"))
    tag = data.get("tag_name", "")
    if ver_tuple(tag) <= ver_tuple(APP_VERSION):
        return None
    want = "Strazh.exe" if FROZEN else "antivirus.py"
    assets = {a["name"]: a["browser_download_url"] for a in data.get("assets", [])}
    if want not in assets or "SHA256SUMS.txt" not in assets:
        return None  # релиз ещё собирается
    sums = http_get(assets["SHA256SUMS.txt"]).decode("utf-8", "replace")
    digest = None
    for line in sums.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2 and parts[-1].lstrip("*") == want:
            digest = parts[0].lower()
    if not digest:
        return None
    return {"version": tag.lstrip("vV"), "notes": (data.get("body") or "").strip(),
            "url": assets[want], "sha256": digest, "name": want}


def download_update(info):
    """Скачивает файл обновления и проверяет его контрольную сумму SHA-256."""
    if not info["url"].startswith("https://github.com/"):
        raise ValueError("Подозрительный адрес обновления — отменено")
    data = http_get(info["url"], timeout=600)
    if hashlib.sha256(data).hexdigest() != info["sha256"]:
        raise ValueError("Контрольная сумма не совпала — файл повреждён или подменён, обновление отменено")
    if info["name"].endswith(".py"):
        compile(data, "antivirus.py", "exec")  # только проверка синтаксиса, код не выполняется
    elif data[:2] != b"MZ":
        raise ValueError("Скачанный файл не похож на программу — отменено")
    UPDATE_DIR.mkdir(parents=True, exist_ok=True)
    dst = UPDATE_DIR / ("new_" + info["name"])
    dst.write_bytes(data)
    return dst


def apply_update(new_file, tray_mode):
    """Запускает маленький скрипт, который дождётся закрытия Стража, заменит файл и запустит новую версию."""
    target = sys.executable if FROZEN else os.path.abspath(__file__)
    task = TASK_NAME if tray_mode else "Strazh-Launch"
    has_task = IS_WIN and run_cmd(["schtasks", "/query", "/tn", task], timeout=15).returncode == 0
    if has_task:
        relaunch = f'schtasks /run /tn "{task}" >nul'
    else:
        exe, args = app_command()
        if FROZEN:
            exe = target
        relaunch = f'start "" "{exe}" {args} {"--tray" if tray_mode else ""}'
    pid = os.getpid()
    bat = UPDATE_DIR / "apply_update.bat"
    bat.write_text(
        "@echo off\r\nchcp 65001 >nul\r\n"
        ":wait\r\n"
        f'tasklist /fi "PID eq {pid}" | find "{pid}" >nul && (ping -n 2 127.0.0.1 >nul & goto wait)\r\n'
        f'copy /y "{target}" "{target}.bak" >nul\r\n'
        f'copy /y "{new_file}" "{target}" >nul || copy /y "{target}.bak" "{target}" >nul\r\n'
        f'del "{new_file}" >nul 2>&1\r\n'
        f"{relaunch}\r\n"
        'del "%~f0"\r\n',
        encoding="utf-8",
    )
    flags = NO_WINDOW | 0x00000200  # + CREATE_NEW_PROCESS_GROUP
    try:
        subprocess.Popen(["cmd", "/c", str(bat)], creationflags=flags | 0x01000000)  # CREATE_BREAKAWAY_FROM_JOB
    except OSError:
        subprocess.Popen(["cmd", "/c", str(bat)], creationflags=flags)
    log(f"Обновление: запуск замены {target}")


# ──────────────────────────────────────────────────────────────────────────────
#  Автозапуск и значок в трее
# ──────────────────────────────────────────────────────────────────────────────

def app_command():
    """Команда, которой запускается программа (exe или python + скрипт)."""
    if FROZEN:
        return sys.executable, ""
    exe = sys.executable
    w = os.path.join(os.path.dirname(exe), "pythonw.exe")
    return (w if os.path.exists(w) else exe), f'"{os.path.abspath(__file__)}"'


def autostart_enabled():
    if not IS_WIN:
        return False
    try:
        return run_cmd(["schtasks", "/query", "/tn", TASK_NAME], timeout=15).returncode == 0
    except Exception:
        return False


def set_autostart(enable):
    """Автозапуск через Планировщик заданий — с правами администратора и без окна UAC."""
    if not IS_WIN:
        return False, "Автозапуск поддерживается только в Windows"
    if enable:
        exe, args = app_command()
        q = lambda x: x.replace("'", "''")
        ps = (
            f"$a=New-ScheduledTaskAction -Execute '{q(exe)}' -Argument '{q((args + ' --tray').strip())}';"
            "$u=\"$env:USERDOMAIN\\$env:USERNAME\";"
            "$t=New-ScheduledTaskTrigger -AtLogOn -User $u; $t.Delay='PT10S';"
            "$p=New-ScheduledTaskPrincipal -UserId $u -RunLevel Highest -LogonType Interactive;"
            "$s=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries "
            "-ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances Parallel;"
            f"Register-ScheduledTask -TaskName '{TASK_NAME}' -Action $a -Trigger $t -Principal $p -Settings $s -Force | Out-Null"
        )
        r = run_cmd(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps], timeout=40)
    else:
        r = run_cmd(["schtasks", "/delete", "/tn", TASK_NAME, "/f"], timeout=20)
    ok = r.returncode == 0
    return ok, "" if ok else (r.stderr or r.stdout or "").strip()


class Tray:
    """Значок в области уведомлений (возле часов). Нужны pystray и pillow."""

    def __init__(self, app):
        self.app = app
        self.icon = None
        try:
            import pystray
            from PIL import Image
        except Exception:
            return
        try:
            img = Image.open(ICON_FILE)
        except Exception:
            from PIL import ImageDraw
            img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
            ImageDraw.Draw(img).polygon([(32, 4), (58, 14), (54, 44), (32, 60), (10, 44), (6, 14)], fill=(79, 140, 255, 255))
        call = lambda fn: (lambda icon, item: app.q.put(("call", fn)))
        menu = pystray.Menu(
            pystray.MenuItem("Открыть Страж", call(app.show_window), default=True),
            pystray.MenuItem("Быстрая проверка", call(lambda: (app.show_window(), app.nb.select(app.tab_scan), app.quick_scan()))),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Выход", call(app.quit_app)),
        )
        self.icon = pystray.Icon("Strazh", img, "Страж — защита активна", menu)
        try:
            self.icon.run_detached()
        except Exception:
            self.icon = None

    def notify(self, text, title="Страж"):
        if self.icon:
            try:
                self.icon.notify(text, title)
            except Exception:
                pass

    def set_title(self, text):
        if self.icon:
            try:
                self.icon.title = text[:120]
            except Exception:
                pass

    def stop(self):
        if self.icon:
            try:
                self.icon.stop()
            except Exception:
                pass


# ──────────────────────────────────────────────────────────────────────────────
#  Фоновый сбор данных о процессах
# ──────────────────────────────────────────────────────────────────────────────

class Sampler(threading.Thread):
    def __init__(self, out_q, cfg):
        super().__init__(daemon=True)
        self.q = out_q
        self.cfg = cfg
        self.stop_flag = threading.Event()
        self.cache = {}      # pid -> (create_time, Process)
        self.hist = {}       # pid -> [cpu...]
        self.ncpu = psutil.cpu_count() or 1
        self.sys_drive = os.environ.get("SystemDrive", "C:") + "\\" if IS_WIN else "/"

    def run(self):
        psutil.cpu_percent(None)
        while not self.stop_flag.is_set():
            try:
                self.q.put(("snapshot", self.sample()))
            except Exception as ex:
                self.q.put(("error", str(ex)))
            self.stop_flag.wait(max(1, float(self.cfg.get("interval", 2))))

    def sample(self):
        rows, seen = [], set()
        attrs = ["pid", "name", "exe", "username", "num_threads", "create_time", "memory_info"]
        for p in psutil.process_iter(attrs):
            info = p.info
            pid = info["pid"]
            seen.add(pid)
            ct = info.get("create_time")
            cached = self.cache.get(pid)
            if not cached or cached[0] != ct:
                self.cache[pid] = (ct, p)
                self.hist[pid] = []
                try:
                    p.cpu_percent(None)
                except Exception:
                    pass
                cpu = 0.0
            else:
                try:
                    cpu = cached[1].cpu_percent(None) / self.ncpu
                except Exception:
                    cpu = 0.0
            h = self.hist.setdefault(pid, [])
            h.append(cpu)
            del h[:-10]
            mem = info.get("memory_info")
            exe = info.get("exe") or ""
            name = info.get("name") or "?"
            score, reasons = analyze_process(name, exe, h) if pid > 4 else (0, [])
            rows.append({
                "pid": pid, "name": name, "exe": exe,
                "user": (info.get("username") or "").split("\\")[-1],
                "user_full": info.get("username") or "",
                "threads": info.get("num_threads") or 0,
                "cpu": cpu, "mem": (mem.rss if mem else 0),
                "score": score, "reasons": reasons, "level": level_of(score),
            })
        for pid in list(self.cache):
            if pid not in seen:
                self.cache.pop(pid, None)
                self.hist.pop(pid, None)
        vm = psutil.virtual_memory()
        try:
            du = psutil.disk_usage(self.sys_drive)
            disk = du.percent
        except Exception:
            disk = 0
        return {
            "rows": rows, "cpu": psutil.cpu_percent(None), "ram": vm.percent,
            "ram_used": vm.used, "ram_total": vm.total, "disk": disk,
        }


# ──────────────────────────────────────────────────────────────────────────────
#  Интерфейс
# ──────────────────────────────────────────────────────────────────────────────

C = {
    "bg": "#0e1116", "panel": "#161b22", "panel2": "#1c2330", "line": "#2a3240",
    "text": "#e6edf3", "muted": "#8b96a5", "accent": "#4f8cff", "accent2": "#3a6fd8",
    "ok": "#3ecf8e", "warn": "#ffb84d", "danger": "#ff5c5c",
    "row_warn": "#3a2f17", "row_danger": "#3d1a1d",
}
FONT = "Segoe UI" if IS_WIN else ("SF Pro Text" if IS_MAC else "DejaVu Sans")
MONO = "Consolas" if IS_WIN else ("Menlo" if IS_MAC else "DejaVu Sans Mono")


def fmt_mb(b):
    return f"{b / 1048576:,.1f}".replace(",", " ")


def fmt_gb(b):
    return f"{b / 1073741824:.1f}"


class StatCard(tk.Frame):
    def __init__(self, master, title, color):
        super().__init__(master, bg=C["panel"], highlightthickness=1, highlightbackground=C["line"])
        self.color = color
        tk.Label(self, text=title, bg=C["panel"], fg=C["muted"], font=(FONT, 9)).pack(anchor="w", padx=14, pady=(10, 0))
        self.value = tk.Label(self, text="—", bg=C["panel"], fg=C["text"], font=(FONT, 20, "bold"))
        self.value.pack(anchor="w", padx=14)
        self.sub = tk.Label(self, text="", bg=C["panel"], fg=C["muted"], font=(FONT, 8))
        self.sub.pack(anchor="w", padx=14)
        self.bar = tk.Canvas(self, height=6, bg=C["panel2"], highlightthickness=0)
        self.bar.pack(fill="x", padx=14, pady=(6, 12))

    def set(self, value, sub="", pct=None, color=None):
        self.value.config(text=value, fg=color or C["text"])
        self.sub.config(text=sub)
        self.bar.delete("all")
        if pct is not None:
            w = self.bar.winfo_width() or 150
            c = self.color
            if pct > 90:
                c = C["danger"]
            elif pct > 75:
                c = C["warn"]
            self.bar.create_rectangle(0, 0, max(2, w * min(pct, 100) / 100), 6, fill=c, width=0)


class Splash(tk.Toplevel):
    """Красивая заставка при запуске."""

    def __init__(self, master):
        super().__init__(master)
        self.overrideredirect(True)
        W, H = 460, 300
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"{W}x{H}+{(sw - W) // 2}+{(sh - H) // 2}")
        self.configure(bg=C["bg"])
        try:
            self.attributes("-alpha", 0.0)
            self.attributes("-topmost", True)
        except Exception:
            pass
        cv = tk.Canvas(self, width=W, height=H, bg=C["bg"], highlightthickness=1, highlightbackground=C["line"])
        cv.pack()
        cx, cy = W // 2, 105
        shield = [cx, cy - 62, cx + 52, cy - 44, cx + 49, cy + 8, cx + 35, cy + 36, cx, cy + 62,
                  cx - 35, cy + 36, cx - 49, cy + 8, cx - 52, cy - 44]
        cv.create_polygon(shield, fill=C["accent"], outline="#bcd6ff", width=3, smooth=False)
        cv.create_line(cx - 26, cy + 2, cx - 7, cy + 21, cx + 28, cy - 18, fill="white", width=11, capstyle="round", joinstyle="round")
        cv.create_text(cx, 200, text=APP_NAME, fill=C["text"], font=(FONT, 24, "bold"))
        cv.create_text(cx, 230, text="монитор процессов и антивирус", fill=C["muted"], font=(FONT, 10))
        self.cv = cv
        self.bar_bg = cv.create_rectangle(80, 262, W - 80, 266, fill=C["panel2"], width=0)
        self.bar = cv.create_rectangle(80, 262, 80, 266, fill=C["accent"], width=0)
        self.W = W
        self.pos = 0.0
        self.alpha = 0.0
        self._tick()

    def _tick(self):
        if not self.winfo_exists():
            return
        self.alpha = min(1.0, self.alpha + 0.1)
        self.pos = min(1.0, self.pos + 0.025)
        try:
            self.attributes("-alpha", self.alpha)
        except Exception:
            pass
        self.cv.coords(self.bar, 80, 262, 80 + (self.W - 160) * self.pos, 266)
        self.after(30, self._tick)

    def close(self):
        try:
            self.destroy()
        except Exception:
            pass


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        ensure_dirs()
        self.cfg = load_config()
        self.title(f"{APP_NAME} {APP_VERSION} — монитор процессов и антивирус")
        self.geometry("1280x780")
        self.minsize(1000, 620)
        self.configure(bg=C["bg"])
        self.q = queue.Queue()
        self.snapshot = None
        self.rows_by_pid = {}
        self.sort_state = {}
        self.alerted = set()
        self.scan_stop = threading.Event()
        self.scan_running = False
        self.me = getpass.getuser().lower()
        self.withdraw()
        try:
            if IS_WIN and os.path.exists(ICON_FILE):
                self.iconbitmap(default=ICON_FILE)
        except Exception:
            pass
        self.splash = None if START_IN_TRAY else Splash(self)

        self._style()
        self._build_header()
        self._build_tabs()
        self._build_status()

        self.sampler = Sampler(self.q, self.cfg)
        self.sampler.start()
        self.after(150, self._poll)
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.refresh_startup()
        self.refresh_quarantine()
        self.tray = Tray(self)
        self.updating = False
        load_signatures()
        self.after(20_000, self._update_loop)
        if START_IN_TRAY and not self.tray.icon:
            self.after(100, self.show_window)  # трея нет — просто показываем окно
        elif not START_IN_TRAY:
            self.after(1400, self._finish_splash)

    # ── окно, заставка, трей ──────────────────────────────────────────────────
    def _finish_splash(self):
        if self.splash:
            self.splash.close()
            self.splash = None
        self.show_window(fade=True)

    def show_window(self, fade=False):
        self.deiconify()
        self.state("normal")
        if fade:
            try:
                self.attributes("-alpha", 0.0)
                self._fade(0.0)
            except Exception:
                pass
        self.lift()
        self.focus_force()
        self.attributes("-topmost", True)
        self.after(300, lambda: self.attributes("-topmost", False))

    def _fade(self, a):
        a = min(1.0, a + 0.08)
        self.attributes("-alpha", a)
        if a < 1.0:
            self.after(15, lambda: self._fade(a))

    def hide_window(self):
        self.withdraw()
        if not getattr(self, "_hint_shown", False):
            self._hint_shown = True
            self.tray.notify("Страж продолжает работать в фоне. Значок — возле часов.")

    def quit_app(self):
        self.sampler.stop_flag.set()
        self.scan_stop.set()
        self.tray.stop()
        self.destroy()

    # ── обновления ────────────────────────────────────────────────────────────
    def _update_loop(self):
        if self.cfg.get("auto_update", True):
            self.check_updates(manual=False)
        self.after(6 * 3600 * 1000, self._update_loop)  # каждые 6 часов

    def check_updates(self, manual=True):
        if self.updating:
            return
        post = lambda fn: self.q.put(("call", fn))

        def work():
            sig_n, info, err = None, None, ""
            try:
                sig_n = update_signatures()
            except Exception as ex:
                err = f"база угроз: {ex}"
            try:
                info = check_update()
            except urllib.error.HTTPError as ex:
                err = "релизов пока нет" if ex.code == 404 else f"GitHub ответил {ex.code}"
            except Exception as ex:
                err = str(ex)
            post(lambda: self._update_checked(info, sig_n, err, manual))

        threading.Thread(target=work, daemon=True).start()

    def _update_checked(self, info, sig_n, err, manual):
        stamp = f"{datetime.datetime.now():%d.%m %H:%M}"
        sig_txt = f"база угроз: {sig_n} записей" if sig_n is not None else ""
        if hasattr(self, "upd_label"):
            self.upd_label.config(text=f"Проверено {stamp}. " + (f"Есть версия {info['version']}" if info else "Установлена последняя версия")
                                  + (f" · {sig_txt}" if sig_txt else "") + (f" · ошибка: {err}" if err and manual else ""))
        if not info:
            if manual:
                messagebox.showinfo(APP_NAME, f"У вас последняя версия ({APP_VERSION}).\n{sig_txt}" + (f"\n\nПримечание: {err}" if err else ""))
            return
        if not IS_WIN:
            messagebox.showinfo(APP_NAME, f"Доступна версия {info['version']}. Скачайте antivirus.py со страницы github.com/{UPDATE_REPO}/releases")
            return
        hidden = self.state() == "withdrawn"
        if hidden and self.cfg.get("auto_update", True):
            self.tray.notify(f"Устанавливаю обновление {info['version']}…")
            self._install_update(info, tray_mode=True)
            return
        notes = info["notes"][:600] or "Исправления и улучшения"
        if messagebox.askyesno(APP_NAME, f"Доступна новая версия Стража: {info['version']}\n(у вас {APP_VERSION})\n\n"
                                         f"Что нового:\n{notes}\n\nОбновить сейчас? Программа перезапустится."):
            self._install_update(info, tray_mode=False)

    def _install_update(self, info, tray_mode):
        self.updating = True
        self.set_status(f"Скачиваю обновление {info['version']}…", C["accent"])
        post = lambda fn: self.q.put(("call", fn))

        def work():
            try:
                new_file = download_update(info)
                post(lambda: self._finish_update(new_file, tray_mode, info))
            except Exception as ex:
                msg = str(ex)
                post(lambda: self._update_failed(msg))

        threading.Thread(target=work, daemon=True).start()

    def _finish_update(self, new_file, tray_mode, info):
        try:
            apply_update(new_file, tray_mode)
        except Exception as ex:
            self._update_failed(str(ex))
            return
        log(f"Обновление до {info['version']}")
        self.quit_app()

    def _update_failed(self, msg):
        self.updating = False
        log("Ошибка обновления: " + msg)
        self.set_status("Обновление не удалось: " + msg, C["danger"])
        if self.state() != "withdrawn":
            messagebox.showerror(APP_NAME, "Не удалось обновиться:\n\n" + msg)

    # ── оформление ────────────────────────────────────────────────────────────
    def _style(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure(".", background=C["bg"], foreground=C["text"], font=(FONT, 10), borderwidth=0)
        s.configure("TFrame", background=C["bg"])
        s.configure("Panel.TFrame", background=C["panel"])
        s.configure("TLabel", background=C["bg"], foreground=C["text"])
        s.configure("Muted.TLabel", background=C["bg"], foreground=C["muted"], font=(FONT, 9))
        s.configure("TNotebook", background=C["bg"], borderwidth=0, tabmargins=(12, 6, 12, 0))
        s.configure("TNotebook.Tab", background=C["panel"], foreground=C["muted"], padding=(18, 9), font=(FONT, 10), borderwidth=0)
        s.map("TNotebook.Tab", background=[("selected", C["panel2"])], foreground=[("selected", C["text"])])
        s.configure("Treeview", background=C["panel"], fieldbackground=C["panel"], foreground=C["text"],
                    rowheight=27, borderwidth=0, font=(FONT, 10))
        s.map("Treeview", background=[("selected", C["accent2"])], foreground=[("selected", "#ffffff")])
        s.configure("Treeview.Heading", background=C["panel2"], foreground=C["muted"], font=(FONT, 9, "bold"),
                    borderwidth=0, padding=(6, 6), relief="flat")
        s.map("Treeview.Heading", background=[("active", C["line"])])
        s.configure("TButton", background=C["panel2"], foreground=C["text"], padding=(14, 7), borderwidth=0, focuscolor=C["panel2"])
        s.map("TButton", background=[("active", C["line"]), ("disabled", C["panel"])], foreground=[("disabled", C["muted"])])
        s.configure("Accent.TButton", background=C["accent"], foreground="#ffffff")
        s.map("Accent.TButton", background=[("active", C["accent2"])])
        s.configure("Danger.TButton", background="#5a2227", foreground="#ffd7d9")
        s.map("Danger.TButton", background=[("active", "#7a2a31")])
        s.configure("TEntry", fieldbackground=C["panel2"], foreground=C["text"], insertcolor=C["text"], borderwidth=0, padding=6)
        s.configure("TCheckbutton", background=C["bg"], foreground=C["text"])
        s.configure("TRadiobutton", background=C["bg"], foreground=C["text"])
        s.map("TRadiobutton", background=[("active", C["bg"])])
        s.configure("TCombobox", fieldbackground=C["panel2"], background=C["panel2"], foreground=C["text"], arrowcolor=C["text"])
        s.map("TCombobox", fieldbackground=[("readonly", C["panel2"])], foreground=[("readonly", C["text"])])
        s.map("TCheckbutton", background=[("active", C["bg"])])
        s.configure("Horizontal.TProgressbar", troughcolor=C["panel2"], background=C["accent"], borderwidth=0, thickness=8)
        s.configure("Vertical.TScrollbar", background=C["panel2"], troughcolor=C["panel"], borderwidth=0, arrowcolor=C["muted"])
        s.configure("TSpinbox", fieldbackground=C["panel2"], foreground=C["text"], arrowcolor=C["text"], borderwidth=0)

    def _build_header(self):
        top = tk.Frame(self, bg=C["bg"])
        top.pack(fill="x", padx=16, pady=(14, 6))
        logo = tk.Frame(top, bg=C["bg"])
        logo.pack(side="left", padx=(0, 18))
        tk.Label(logo, text="◆ " + APP_NAME, bg=C["bg"], fg=C["accent"], font=(FONT, 20, "bold")).pack(anchor="w")
        self.shield = tk.Label(logo, text="Защита активна", bg=C["bg"], fg=C["ok"], font=(FONT, 10, "bold"))
        self.shield.pack(anchor="w")
        tk.Label(logo, text=f"{platform.system()} {platform.release()} · {'администратор' if is_admin() else 'обычный пользователь'}",
                 bg=C["bg"], fg=C["muted"], font=(FONT, 8)).pack(anchor="w")

        cards = tk.Frame(top, bg=C["bg"])
        cards.pack(side="left", fill="x", expand=True)
        self.card_cpu = StatCard(cards, "ПРОЦЕССОР", C["accent"])
        self.card_ram = StatCard(cards, "ОПЕРАТИВНАЯ ПАМЯТЬ", "#a371f7")
        self.card_disk = StatCard(cards, "СИСТЕМНЫЙ ДИСК", "#39c5cf")
        self.card_proc = StatCard(cards, "ПРОЦЕССОВ", C["ok"])
        self.card_threat = StatCard(cards, "УГРОЗ", C["danger"])
        for i, c in enumerate((self.card_cpu, self.card_ram, self.card_disk, self.card_proc, self.card_threat)):
            c.grid(row=0, column=i, sticky="nsew", padx=5)
            cards.columnconfigure(i, weight=1)

    def _build_tabs(self):
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=16, pady=(6, 0))
        self.tab_proc = ttk.Frame(self.nb)
        self.tab_apps = ttk.Frame(self.nb)
        self.tab_threat = ttk.Frame(self.nb)
        self.tab_start = ttk.Frame(self.nb)
        self.tab_scan = ttk.Frame(self.nb)
        self.tab_quar = ttk.Frame(self.nb)
        self.tab_dup = ttk.Frame(self.nb)
        self.tab_set = ttk.Frame(self.nb)
        self.nb.add(self.tab_proc, text="  Процессы  ")
        self.nb.add(self.tab_apps, text="  Программы  ")
        self.nb.add(self.tab_threat, text="  Угрозы  ")
        self.nb.add(self.tab_start, text="  Автозагрузка  ")
        self.nb.add(self.tab_scan, text="  Сканер  ")
        self.nb.add(self.tab_quar, text="  Карантин  ")
        self.nb.add(self.tab_dup, text="  Дубликаты  ")
        self.nb.add(self.tab_set, text="  Настройки  ")
        self._tab_processes()
        self._tab_apps()
        self._tab_threats()
        self._tab_startup()
        self._tab_scanner()
        self._tab_quarantine()
        self._tab_duplicates()
        self._tab_settings()

    def _build_status(self):
        self.status = tk.Label(self, text="Запуск…", bg=C["panel"], fg=C["muted"], anchor="w", font=(FONT, 9), padx=14, pady=5)
        self.status.pack(fill="x", side="bottom", pady=(8, 0))

    def set_status(self, text, color=None):
        self.status.config(text=text, fg=color or C["muted"])

    # ── общие помощники для таблиц ────────────────────────────────────────────
    def make_tree(self, parent, columns):
        """columns: [(id, заголовок, ширина, anchor, numeric)]"""
        wrap = ttk.Frame(parent)
        wrap.pack(fill="both", expand=True, padx=2, pady=(6, 0))
        tree = ttk.Treeview(wrap, columns=[c[0] for c in columns], show="headings", selectmode="extended")
        vs = ttk.Scrollbar(wrap, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=vs.set)
        tree.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")
        tree._numeric = {c[0] for c in columns if c[4]}
        tree._titles = {c[0]: c[1] for c in columns}
        for cid, title, width, anchor, _ in columns:
            tree.heading(cid, text=title, command=lambda c=cid, t=tree: self.sort_by(t, c))
            tree.column(cid, width=width, anchor=anchor, stretch=(cid in ("path", "cmd", "details", "reasons", "orig")))
        tree.tag_configure("warn", background=C["row_warn"], foreground="#ffe2b0")
        tree.tag_configure("danger", background=C["row_danger"], foreground="#ffd0d3")
        tree.tag_configure("ok", background=C["panel"])
        tree.tag_configure("unknown", background=C["panel"], foreground=C["muted"])
        return tree

    def sort_by(self, tree, col):
        st = self.sort_state.get(id(tree))
        desc = not st[1] if st and st[0] == col else (col in tree._numeric)
        self.sort_state[id(tree)] = (col, desc)
        for c, t in tree._titles.items():
            tree.heading(c, text=t + ((" ▼" if desc else " ▲") if c == col else ""))
        self.apply_sort(tree)

    def apply_sort(self, tree):
        st = self.sort_state.get(id(tree))
        if not st:
            return
        col, desc = st
        num = col in tree._numeric

        def key(iid):
            v = tree.set(iid, col)
            if num:
                try:
                    return float(str(v).replace(" ", "").replace(",", ".") or 0)
                except ValueError:
                    return 0.0
            return str(v).lower()

        for i, iid in enumerate(sorted(tree.get_children(""), key=key, reverse=desc)):
            tree.move(iid, "", i)

    def sync_tree(self, tree, rows):
        """rows: [(iid, values, tag)] — обновляет таблицу без мерцания и с сохранением выделения."""
        existing = set(tree.get_children(""))
        ids = []
        for iid, vals, tag in rows:
            ids.append(iid)
            if iid in existing:
                tree.item(iid, values=vals, tags=(tag,))
            else:
                tree.insert("", "end", iid=iid, values=vals, tags=(tag,))
        keep = set(ids)
        gone = [i for i in existing if i not in keep]
        if gone:
            tree.delete(*gone)
        self.apply_sort(tree)

    def toolbar(self, parent):
        bar = ttk.Frame(parent)
        bar.pack(fill="x", pady=(12, 0), padx=2)
        return bar

    # ── вкладка «Процессы» ────────────────────────────────────────────────────
    def _tab_processes(self):
        bar = self.toolbar(self.tab_proc)
        ttk.Label(bar, text="Поиск:").pack(side="left")
        self.proc_search = tk.StringVar()
        self.proc_search.trace_add("write", lambda *_: self.render_processes())
        ttk.Entry(bar, textvariable=self.proc_search, width=28).pack(side="left", padx=(6, 12))
        self.only_sus = tk.BooleanVar()
        ttk.Checkbutton(bar, text="Только подозрительные", variable=self.only_sus,
                        command=self.render_processes).pack(side="left")
        ttk.Button(bar, text="Завершить", style="Danger.TButton", command=self.kill_selected).pack(side="right", padx=(6, 0))
        ttk.Button(bar, text="Проверить файл", command=self.check_selected_process).pack(side="right", padx=(6, 0))
        ttk.Button(bar, text="Открыть папку", command=self.open_selected_process).pack(side="right", padx=(6, 0))
        ttk.Button(bar, text="Подробнее", command=self.details_selected).pack(side="right", padx=(6, 0))

        self.tree_proc = self.make_tree(self.tab_proc, [
            ("name", "Имя", 210, "w", False),
            ("pid", "PID", 70, "e", True),
            ("cpu", "ЦП %", 75, "e", True),
            ("mem", "ОЗУ, МБ", 95, "e", True),
            ("threads", "Потоки", 70, "e", True),
            ("user", "Пользователь", 130, "w", False),
            ("risk", "Риск", 120, "w", False),
            ("path", "Путь к файлу", 420, "w", False),
        ])
        self.sort_state[id(self.tree_proc)] = ("cpu", True)
        self.tree_proc.heading("cpu", text="ЦП % ▼")
        self.tree_proc.bind("<Double-1>", lambda e: self.details_selected())
        self.tree_proc.bind("<Delete>", lambda e: self.kill_selected())

        self.menu_proc = tk.Menu(self, tearoff=0, bg=C["panel2"], fg=C["text"], activebackground=C["accent"],
                                 activeforeground="#fff", bd=0)
        self.menu_proc.add_command(label="Подробнее", command=self.details_selected)
        self.menu_proc.add_command(label="Открыть папку с файлом", command=self.open_selected_process)
        self.menu_proc.add_command(label="Проверить файл на вирусы", command=self.check_selected_process)
        self.menu_proc.add_command(label="Скопировать путь", command=self.copy_selected_path)
        self.menu_proc.add_separator()
        self.menu_proc.add_command(label="Завершить процесс", command=self.kill_selected)
        self.menu_proc.add_command(label="Завершить и отправить в карантин", command=self.kill_and_quarantine)
        self.tree_proc.bind("<Button-3>", self._popup_proc)
        self.tree_proc.bind("<Button-2>", self._popup_proc)

    def _popup_proc(self, e):
        iid = self.tree_proc.identify_row(e.y)
        if iid:
            if iid not in self.tree_proc.selection():
                self.tree_proc.selection_set(iid)
            self.menu_proc.tk_popup(e.x_root, e.y_root)

    def render_processes(self):
        if not self.snapshot:
            return
        q = self.proc_search.get().strip().lower()
        rows = []
        for r in self.snapshot["rows"]:
            if self.only_sus.get() and r["level"] == "ok":
                continue
            if q and q not in r["name"].lower() and q not in r["exe"].lower() and q != str(r["pid"]):
                continue
            risk = LEVEL_TEXT[r["level"]] if r["level"] != "ok" else ""
            rows.append((f"p{r['pid']}", (
                r["name"], r["pid"], f"{r['cpu']:.1f}", fmt_mb(r["mem"]), r["threads"],
                r["user"], risk, r["exe"] or "— (нет доступа)",
            ), r["level"]))
        self.sync_tree(self.tree_proc, rows)

    def selected_rows(self, tree=None):
        tree = tree or self.tree_proc
        res = []
        for iid in tree.selection():
            if iid.startswith("p") or iid.startswith("t"):
                pid = int(iid[1:])
                if pid in self.rows_by_pid:
                    res.append(self.rows_by_pid[pid])
        return res

    def kill_selected(self, tree=None):
        rows = self.selected_rows(tree)
        if not rows:
            return
        names = ", ".join(f"{r['name']} ({r['pid']})" for r in rows[:5]) + (" …" if len(rows) > 5 else "")
        if not messagebox.askyesno(APP_NAME, f"Завершить процесс(ы)?\n\n{names}\n\nНесохранённые данные в этих программах пропадут."):
            return
        self._kill(rows)

    def _kill(self, rows):
        errors = []
        for r in rows:
            try:
                p = psutil.Process(r["pid"])
                p.terminate()
                try:
                    p.wait(3)
                except psutil.TimeoutExpired:
                    p.kill()
                log(f"Завершён процесс {r['name']} (PID {r['pid']})")
            except psutil.NoSuchProcess:
                pass
            except psutil.AccessDenied:
                errors.append(f"{r['name']}: нет прав (запустите от имени администратора)")
            except Exception as ex:
                errors.append(f"{r['name']}: {ex}")
        if errors:
            messagebox.showwarning(APP_NAME, "Не удалось завершить:\n\n" + "\n".join(errors))
        else:
            self.set_status(f"Завершено процессов: {len(rows)}", C["ok"])

    def kill_and_quarantine(self, tree=None):
        rows = [r for r in self.selected_rows(tree) if r["exe"]]
        if not rows:
            return
        if not messagebox.askyesno(APP_NAME, "Завершить процесс и переместить его файл в карантин?\n\n" +
                                   "\n".join(r["exe"] for r in rows[:5])):
            return
        self._kill(rows)
        time.sleep(0.5)
        for r in rows:
            try:
                quarantine_file(r["exe"], "; ".join(r["reasons"]) or "вручную")
            except Exception as ex:
                messagebox.showerror(APP_NAME, f"Не удалось переместить {r['exe']}:\n{ex}")
        self.refresh_quarantine()

    def open_selected_process(self, tree=None):
        for r in self.selected_rows(tree)[:1]:
            if r["exe"]:
                open_in_explorer(r["exe"])

    def copy_selected_path(self):
        rows = self.selected_rows()
        if rows:
            self.clipboard_clear()
            self.clipboard_append("\n".join(r["exe"] for r in rows if r["exe"]))
            self.set_status("Путь скопирован")

    def check_selected_process(self, tree=None):
        rows = [r for r in self.selected_rows(tree) if r["exe"]]
        if not rows:
            messagebox.showinfo(APP_NAME, "У процесса нет доступного файла (попробуйте запустить от имени администратора).")
            return
        self.nb.select(self.tab_scan)
        self.start_scan([r["exe"] for r in rows])

    def details_selected(self, tree=None):
        rows = self.selected_rows(tree)
        if not rows:
            return
        r = rows[0]
        win = tk.Toplevel(self)
        win.title(f"{r['name']} — подробности")
        win.geometry("720x520")
        win.configure(bg=C["bg"])
        color = C[r["level"]] if r["level"] != "ok" else C["ok"]
        tk.Label(win, text=r["name"], bg=C["bg"], fg=C["text"], font=(FONT, 16, "bold")).pack(anchor="w", padx=18, pady=(16, 0))
        tk.Label(win, text=LEVEL_TEXT[r["level"]] + (f"  ·  {r['score']} баллов риска" if r["score"] else ""),
                 bg=C["bg"], fg=color, font=(FONT, 10, "bold")).pack(anchor="w", padx=18)
        txt = tk.Text(win, bg=C["panel"], fg=C["text"], font=(MONO, 10), bd=0, padx=14, pady=12, wrap="word",
                      insertbackground=C["text"])
        txt.pack(fill="both", expand=True, padx=18, pady=14)

        def put(line=""):
            txt.configure(state="normal")
            txt.insert("end", line + "\n")
            txt.configure(state="disabled")

        try:
            p = psutil.Process(r["pid"])
            with p.oneshot():
                started = datetime.datetime.fromtimestamp(p.create_time()).strftime("%d.%m.%Y %H:%M:%S")
                try:
                    parent = p.parent()
                    parent_s = f"{parent.name()} (PID {parent.pid})" if parent else "—"
                except Exception:
                    parent_s = "—"
                try:
                    cmdline = " ".join(p.cmdline())
                except Exception:
                    cmdline = "нет доступа"
                try:
                    conns = len(p.net_connections()) if hasattr(p, "net_connections") else len(p.connections())
                except Exception:
                    conns = "нет доступа"
        except Exception:
            started = parent_s = cmdline = "процесс уже завершён"
            conns = "—"
        put(f"PID:              {r['pid']}")
        put(f"Пользователь:     {r['user_full']}")
        put(f"Запущен:          {started}")
        put(f"Родитель:         {parent_s}")
        put(f"ЦП / ОЗУ:         {r['cpu']:.1f}%  /  {fmt_mb(r['mem'])} МБ")
        put(f"Сетевых соедин.:  {conns}")
        put(f"Файл:             {r['exe'] or '—'}")
        put(f"Командная строка: {cmdline}")
        put()
        put("ПОЧЕМУ ПОДОЗРИТЕЛЬНО:" if r["reasons"] else "Подозрительных признаков не найдено.")
        for why in r["reasons"]:
            put("  • " + why)
        put()
        if r["exe"] and os.path.exists(r["exe"]):
            put("Считаю SHA-256 и проверяю подпись…")

            def work():
                d = sha256_of(r["exe"])
                sig = signature_status(r["exe"])
                lines = [f"SHA-256:          {d or 'не удалось'}"]
                if sig:
                    lines.append(f"Цифровая подпись: {sig}")
                if d in KNOWN_BAD:
                    lines.append("!!! Известный вредоносный файл: " + KNOWN_BAD[d])
                self.q.put(("call", lambda: [put(x) for x in lines] if win.winfo_exists() else None))

            threading.Thread(target=work, daemon=True).start()

        btns = ttk.Frame(win)
        btns.pack(fill="x", padx=18, pady=(0, 16))
        ttk.Button(btns, text="Закрыть", command=win.destroy).pack(side="right")
        ttk.Button(btns, text="Проверить на вирусы", style="Accent.TButton",
                   command=lambda: (win.destroy(), self.nb.select(self.tab_scan), self.start_scan([r["exe"]])) if r["exe"] else None
                   ).pack(side="right", padx=6)

    # ── вкладка «Программы» ───────────────────────────────────────────────────
    def _tab_apps(self):
        bar = self.toolbar(self.tab_apps)
        self.only_mine = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar, text="Только мои программы (без системных служб)", variable=self.only_mine,
                        command=self.render_apps).pack(side="left")
        ttk.Button(bar, text="Закрыть программу", style="Danger.TButton", command=self.kill_app).pack(side="right", padx=(6, 0))
        ttk.Button(bar, text="Открыть папку", command=self.open_app_folder).pack(side="right", padx=(6, 0))
        self.tree_apps = self.make_tree(self.tab_apps, [
            ("name", "Программа", 260, "w", False),
            ("count", "Процессов", 90, "e", True),
            ("cpu", "ЦП %", 80, "e", True),
            ("mem", "ОЗУ, МБ", 100, "e", True),
            ("risk", "Риск", 120, "w", False),
            ("path", "Путь", 500, "w", False),
        ])
        self.sort_state[id(self.tree_apps)] = ("mem", True)
        self.tree_apps.heading("mem", text="ОЗУ, МБ ▼")
        self.app_groups = {}

    def _is_system(self, r):
        e = os.path.normcase(r["exe"])
        if IS_WIN:
            u = r["user_full"].upper()
            if "SYSTEM" in u or "LOCAL SERVICE" in u or "NETWORK SERVICE" in u or "СИСТЕМА" in u:
                return True
            return e.startswith(WINDIR) and r["name"].lower() != "explorer.exe"
        return r["user"].lower() != self.me

    def render_apps(self):
        if not self.snapshot:
            return
        groups = {}
        for r in self.snapshot["rows"]:
            if r["pid"] <= 4:
                continue
            if self.only_mine.get() and (self._is_system(r) or not r["exe"]):
                continue
            key = os.path.normcase(r["exe"]) or r["name"].lower()
            g = groups.setdefault(key, {"name": r["name"], "exe": r["exe"], "pids": [], "cpu": 0.0, "mem": 0, "score": 0})
            g["pids"].append(r["pid"])
            g["cpu"] += r["cpu"]
            g["mem"] += r["mem"]
            g["score"] = max(g["score"], r["score"])
        self.app_groups = {}
        rows = []
        for i, (key, g) in enumerate(groups.items()):
            iid = "a" + hashlib.md5(key.encode("utf-8", "ignore")).hexdigest()[:12]
            self.app_groups[iid] = g
            lvl = level_of(g["score"])
            nice = os.path.splitext(g["name"])[0]
            rows.append((iid, (nice, len(g["pids"]), f"{g['cpu']:.1f}", fmt_mb(g["mem"]),
                               LEVEL_TEXT[lvl] if lvl != "ok" else "", g["exe"]), lvl))
        self.sync_tree(self.tree_apps, rows)

    def kill_app(self):
        sel = [self.app_groups[i] for i in self.tree_apps.selection() if i in self.app_groups]
        if not sel:
            return
        g = sel[0]
        if not messagebox.askyesno(APP_NAME, f"Закрыть «{g['name']}» ({len(g['pids'])} процесс.)?"):
            return
        self._kill([self.rows_by_pid[p] for p in g["pids"] if p in self.rows_by_pid])

    def open_app_folder(self):
        sel = [self.app_groups[i] for i in self.tree_apps.selection() if i in self.app_groups]
        if sel and sel[0]["exe"]:
            open_in_explorer(sel[0]["exe"])

    # ── вкладка «Угрозы» ──────────────────────────────────────────────────────
    def _tab_threats(self):
        bar = self.toolbar(self.tab_threat)
        self.threat_label = ttk.Label(bar, text="Подозрительных процессов не найдено", style="Muted.TLabel")
        self.threat_label.pack(side="left")
        ttk.Button(bar, text="Завершить и в карантин", style="Danger.TButton",
                   command=lambda: self.kill_and_quarantine(self.tree_threat)).pack(side="right", padx=(6, 0))
        ttk.Button(bar, text="Завершить", command=lambda: self.kill_selected(self.tree_threat)).pack(side="right", padx=(6, 0))
        ttk.Button(bar, text="Проверить файл", command=lambda: self.check_selected_process(self.tree_threat)).pack(side="right", padx=(6, 0))
        ttk.Button(bar, text="Подробнее", command=lambda: self.details_selected(self.tree_threat)).pack(side="right", padx=(6, 0))
        self.tree_threat = self.make_tree(self.tab_threat, [
            ("name", "Процесс", 190, "w", False),
            ("pid", "PID", 70, "e", True),
            ("risk", "Уровень", 120, "w", False),
            ("score", "Баллы", 70, "e", True),
            ("reasons", "Почему", 520, "w", False),
            ("path", "Путь", 300, "w", False),
        ])
        self.sort_state[id(self.tree_threat)] = ("score", True)
        self.tree_threat.bind("<Double-1>", lambda e: self.details_selected(self.tree_threat))
        ttk.Label(self.tab_threat, style="Muted.TLabel",
                  text="Эвристика показывает подозрения, а не точный диагноз. Перед удалением проверьте файл на вкладке «Сканер».").pack(anchor="w", pady=6)

    def render_threats(self):
        rows = []
        for r in self.snapshot["rows"]:
            if r["level"] == "ok":
                continue
            rows.append((f"t{r['pid']}", (r["name"], r["pid"], LEVEL_TEXT[r["level"]], r["score"],
                                           "; ".join(r["reasons"]), r["exe"]), r["level"]))
        self.sync_tree(self.tree_threat, rows)
        n_d = sum(1 for x in rows if x[2] == "danger")
        n_w = len(rows) - n_d
        if rows:
            self.threat_label.config(text=f"Опасных: {n_d}   ·   Подозрительных: {n_w}")
        else:
            self.threat_label.config(text="Подозрительных процессов не найдено ✓")
        self.nb.tab(self.tab_threat, text=f"  Угрозы ({len(rows)})  " if rows else "  Угрозы  ")
        return n_d, n_w

    # ── вкладка «Автозагрузка» ────────────────────────────────────────────────
    def _tab_startup(self):
        bar = self.toolbar(self.tab_start)
        ttk.Label(bar, text="Программы, которые запускаются вместе с системой", style="Muted.TLabel").pack(side="left")
        ttk.Button(bar, text="Обновить", command=self.refresh_startup).pack(side="right", padx=(6, 0))
        ttk.Button(bar, text="Проверить файл", style="Accent.TButton", command=self.check_startup).pack(side="right", padx=(6, 0))
        ttk.Button(bar, text="Открыть папку", command=self.open_startup).pack(side="right", padx=(6, 0))
        self.tree_start = self.make_tree(self.tab_start, [
            ("name", "Название", 220, "w", False),
            ("risk", "Риск", 120, "w", False),
            ("where", "Где прописано", 230, "w", False),
            ("cmd", "Команда / файл", 600, "w", False),
        ])
        self.start_items = {}

    def refresh_startup(self):
        rows = []
        self.start_items = {}
        for i, (name, cmd, where) in enumerate(startup_entries()):
            path = extract_path(cmd)
            score, reasons = 0, []
            if path and os.path.isfile(path):
                score, reasons, _ = analyze_file(path)
                pe, _ = analyze_process(os.path.basename(path), path, [])
                score += pe
            elif path and not os.path.exists(path) and where.startswith("Реестр"):
                reasons.append("Файл не найден (мусорная запись)")
            if re.search(r"powershell.*(-enc|hidden)|mshta|wscript|regsvr32\s+/s\s+/i:http", cmd, re.I):
                score += 50
                reasons.append("Подозрительная команда запуска")
            lvl = level_of(score)
            iid = f"s{i}"
            self.start_items[iid] = {"path": path, "cmd": cmd, "reasons": reasons}
            rows.append((iid, (name, LEVEL_TEXT[lvl] if lvl != "ok" else "", where, cmd), lvl))
        self.sync_tree(self.tree_start, rows)

    def check_startup(self):
        paths = [self.start_items[i]["path"] for i in self.tree_start.selection()
                 if i in self.start_items and os.path.isfile(self.start_items[i]["path"])]
        if paths:
            self.nb.select(self.tab_scan)
            self.start_scan(paths)

    def open_startup(self):
        for i in self.tree_start.selection()[:1]:
            p = self.start_items.get(i, {}).get("path")
            if p and os.path.exists(p):
                open_in_explorer(p)

    # ── вкладка «Сканер» ──────────────────────────────────────────────────────
    def _tab_scanner(self):
        top = ttk.Frame(self.tab_scan)
        top.pack(fill="x", pady=(12, 0), padx=2)
        ttk.Button(top, text="Быстрая проверка", style="Accent.TButton", command=self.quick_scan).pack(side="left")
        ttk.Button(top, text="Проверить файл…", command=self.pick_file).pack(side="left", padx=6)
        ttk.Button(top, text="Проверить папку…", command=self.pick_folder).pack(side="left")
        self.btn_stop = ttk.Button(top, text="Стоп", command=self.scan_stop.set, state="disabled")
        self.btn_stop.pack(side="left", padx=6)

        eng = engine_name()
        self.use_heur = tk.BooleanVar(value=True)
        self.use_engine = tk.BooleanVar(value=bool(eng))
        self.use_vt = tk.BooleanVar(value=bool(self.cfg.get("vt_key")))
        opts = ttk.Frame(self.tab_scan)
        opts.pack(fill="x", pady=(10, 0), padx=2)
        ttk.Checkbutton(opts, text="Эвристика", variable=self.use_heur).pack(side="left")
        cb = ttk.Checkbutton(opts, text=f"Антивирус: {eng or 'не найден'}", variable=self.use_engine)
        cb.pack(side="left", padx=14)
        if not eng:
            cb.state(["disabled"])
        ttk.Checkbutton(opts, text="VirusTotal (70+ антивирусов, нужен ключ)", variable=self.use_vt).pack(side="left")

        prog = ttk.Frame(self.tab_scan)
        prog.pack(fill="x", pady=(10, 0), padx=2)
        self.scan_info = ttk.Label(prog, text="Выберите, что проверить. «Быстрая проверка» — Загрузки, Рабочий стол, Temp и автозагрузка.",
                                   style="Muted.TLabel")
        self.scan_info.pack(anchor="w")
        self.scan_bar = ttk.Progressbar(prog, mode="determinate")
        self.scan_bar.pack(fill="x", pady=(6, 0))

        bar2 = ttk.Frame(self.tab_scan)
        bar2.pack(fill="x", pady=(10, 0), padx=2)
        self.only_bad = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar2, text="Показывать только найденное", variable=self.only_bad, command=self.render_scan).pack(side="left")
        ttk.Button(bar2, text="В карантин", style="Danger.TButton", command=self.quarantine_scan_selected).pack(side="right", padx=(6, 0))
        ttk.Button(bar2, text="Открыть папку", command=self.open_scan_selected).pack(side="right", padx=(6, 0))

        self.tree_scan = self.make_tree(self.tab_scan, [
            ("file", "Файл", 260, "w", False),
            ("verdict", "Результат", 130, "w", False),
            ("details", "Подробности", 520, "w", False),
            ("path", "Путь", 360, "w", False),
        ])
        self.tree_scan.bind("<Double-1>", lambda e: self.show_scan_details())
        self.scan_results = {}

    def pick_file(self):
        p = filedialog.askopenfilenames(title="Выберите файлы для проверки")
        if p:
            self.start_scan(list(p))

    def pick_folder(self):
        p = filedialog.askdirectory(title="Выберите папку для проверки")
        if p:
            self.start_scan([p])

    def quick_scan(self):
        targets = [str(Path.home() / "Downloads"), str(Path.home() / "Desktop")]
        targets += [t for t in TEMP_DIRS if os.path.isdir(t)]
        for _, cmd, _ in startup_entries():
            p = extract_path(cmd)
            if p and os.path.isfile(p):
                targets.append(p)
        self.start_scan([t for t in targets if os.path.exists(t)], quick=True)

    def start_scan(self, targets, quick=False):
        if self.scan_running:
            messagebox.showinfo(APP_NAME, "Проверка уже идёт. Дождитесь окончания или нажмите «Стоп».")
            return
        self.scan_running = True
        self.scan_stop.clear()
        self.btn_stop.state(["!disabled"])
        self.scan_results = {}
        self.tree_scan.delete(*self.tree_scan.get_children())
        self.scan_bar.config(value=0, maximum=1)
        cfg = {"heur": self.use_heur.get(), "engine": self.use_engine.get() and bool(engine_name()),
               "vt": self.use_vt.get(), "key": self.cfg.get("vt_key", ""), "quick": quick}
        threading.Thread(target=self._scan_worker, args=(targets, cfg), daemon=True).start()

    def _scan_worker(self, targets, cfg):
        post = lambda *a: self.q.put(a)
        t0 = time.time()
        post("scan_info", "Собираю список файлов…")
        files = []
        for t in targets:
            if os.path.isfile(t):
                files.append(t)
            elif os.path.isdir(t):
                for root, dirs, fns in os.walk(t):
                    if self.scan_stop.is_set():
                        break
                    if cfg["quick"] and root.count(os.sep) - t.count(os.sep) > 3:
                        dirs[:] = []
                    for fn in fns:
                        if not cfg["quick"] or os.path.splitext(fn)[1].lower() in EXEC_EXT | {".zip", ".rar", ".7z", ".iso", ".docm", ".xlsm"}:
                            files.append(os.path.join(root, fn))
        total = len(files)
        post("scan_max", max(total, 1))
        found = 0
        vt_last = 0.0
        single = len(files) <= 3

        for i, f in enumerate(files, 1):
            if self.scan_stop.is_set():
                break
            if i % 5 == 0 or single:
                post("scan_info", f"Проверка {i} из {total}: {f}")
            score, reasons, digest = (analyze_file(f) if cfg["heur"] else (0, [], None))
            if cfg["vt"] and (single or score >= 20):
                digest = digest or sha256_of(f)
                if digest:
                    wait = 15.5 - (time.time() - vt_last)
                    if wait > 0 and not single:
                        post("scan_info", f"VirusTotal: пауза {int(wait)} с (лимит бесплатного ключа)…")
                        time.sleep(wait)
                    vt_last = time.time()
                    st, text = virustotal_lookup(digest, cfg["key"])
                    reasons.append(text)
                    if st == "danger":
                        score += 100
                    elif st == "warn":
                        score += 30
            lvl = level_of(score)
            if lvl != "ok":
                found += 1
            post("scan_result", f, lvl, reasons, digest)
            post("scan_progress", i)

        if cfg["engine"] and not self.scan_stop.is_set():
            name = engine_name()
            for t in targets:
                if self.scan_stop.is_set():
                    break
                post("scan_info", f"{name}: проверяю {t} … (может занять несколько минут)")
                ok, hits, err = scan_with_engine(t)
                if not ok and err:
                    post("scan_engine_err", f"{name}: {err}")
                for path, threat in hits.items():
                    found += 1
                    post("scan_engine_hit", path, f"{name}: {threat}")
                if ok and os.path.isfile(t) and not hits:
                    post("scan_engine_clean", os.path.normcase(t), f"{name}: угроз нет")

        took = time.time() - t0
        post("scan_done", total, found, took, self.scan_stop.is_set())

    def _scan_add(self, path, level, reasons, digest=None):
        key = os.path.normcase(path)
        old = self.scan_results.get(key)
        if old:
            order = {"ok": 0, "unknown": 0, "warn": 1, "danger": 2}
            if order[level] > order[old["level"]]:
                old["level"] = level
            old["reasons"] += [r for r in reasons if r not in old["reasons"]]
        else:
            self.scan_results[key] = {"path": path, "level": level, "reasons": list(reasons), "digest": digest}

    def render_scan(self):
        rows = []
        for i, (key, r) in enumerate(self.scan_results.items()):
            if self.only_bad.get() and r["level"] == "ok":
                continue
            verdict = {"danger": "ВИРУС / ОПАСНО", "warn": "Подозрительно", "ok": "Чисто"}[r["level"]]
            iid = "f" + hashlib.md5(key.encode("utf-8", "ignore")).hexdigest()[:16]
            r["iid"] = iid
            rows.append((iid, (os.path.basename(r["path"]), verdict, "; ".join(r["reasons"]) or "—", r["path"]), r["level"]))
        self.sync_tree(self.tree_scan, rows)

    def _scan_selected(self):
        sel = set(self.tree_scan.selection())
        return [r for r in self.scan_results.values() if r.get("iid") in sel]

    def show_scan_details(self):
        for r in self._scan_selected()[:1]:
            msg = f"{r['path']}\n\nSHA-256: {r.get('digest') or '—'}\n\n" + ("\n".join("• " + x for x in r["reasons"]) or "Подозрительного не найдено")
            messagebox.showinfo(APP_NAME, msg)

    def open_scan_selected(self):
        for r in self._scan_selected()[:1]:
            open_in_explorer(r["path"])

    def quarantine_scan_selected(self):
        sel = [r for r in self._scan_selected() if os.path.exists(r["path"])]
        if not sel:
            return
        if not messagebox.askyesno(APP_NAME, f"Переместить в карантин файлов: {len(sel)}?\nИх можно будет восстановить."):
            return
        moved = 0
        for r in sel:
            try:
                quarantine_file(r["path"], "; ".join(r["reasons"]))
                moved += 1
                self.scan_results.pop(os.path.normcase(r["path"]), None)
            except PermissionError:
                messagebox.showerror(APP_NAME, f"Файл занят или нет прав:\n{r['path']}\n\nЗавершите процесс этой программы и повторите.")
            except Exception as ex:
                messagebox.showerror(APP_NAME, f"Ошибка:\n{r['path']}\n{ex}")
        self.render_scan()
        self.refresh_quarantine()
        self.set_status(f"В карантин перемещено: {moved}", C["ok"])

    # ── вкладка «Карантин» ────────────────────────────────────────────────────
    def _tab_quarantine(self):
        bar = self.toolbar(self.tab_quar)
        ttk.Label(bar, text=f"Файлы в карантине обезврежены и не могут запуститься. Папка: {QUAR_DIR}", style="Muted.TLabel").pack(side="left")
        ttk.Button(bar, text="Удалить навсегда", style="Danger.TButton", command=self.quar_delete).pack(side="right", padx=(6, 0))
        ttk.Button(bar, text="Восстановить", command=self.quar_restore).pack(side="right", padx=(6, 0))
        self.tree_quar = self.make_tree(self.tab_quar, [
            ("name", "Файл", 240, "w", False),
            ("date", "Дата", 140, "w", False),
            ("reasons", "Причина", 420, "w", False),
            ("orig", "Откуда", 420, "w", False),
        ])

    def refresh_quarantine(self):
        items = quar_load()
        rows = []
        for i, it in enumerate(items):
            rows.append((f"q{i}", (os.path.basename(it["original"]), it.get("date", ""), it.get("reason", ""), it["original"]), "warn"))
        self.sync_tree(self.tree_quar, rows)
        self.nb.tab(self.tab_quar, text=f"  Карантин ({len(items)})  " if items else "  Карантин  ")

    def _quar_selected(self):
        return sorted(int(i[1:]) for i in self.tree_quar.selection())

    def quar_restore(self):
        idx = self._quar_selected()
        if not idx or not messagebox.askyesno(APP_NAME, "Восстановить выбранные файлы на прежнее место?\nДелайте это, только если уверены, что файл безопасен."):
            return
        items = quar_load()
        for i in reversed(idx):
            it = items[i]
            src = QUAR_DIR / it["file"]
            dst = it["original"]
            try:
                if os.path.exists(dst):
                    dst = dst + ".restored"
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.move(str(src), dst)
                items.pop(i)
                log(f"Восстановлен из карантина: {dst}")
            except Exception as ex:
                messagebox.showerror(APP_NAME, f"Не удалось восстановить {dst}:\n{ex}")
        quar_save(items)
        self.refresh_quarantine()

    def quar_delete(self):
        idx = self._quar_selected()
        if not idx or not messagebox.askyesno(APP_NAME, f"Удалить навсегда файлов: {len(idx)}?\nЭто действие нельзя отменить."):
            return
        items = quar_load()
        for i in reversed(idx):
            try:
                (QUAR_DIR / items[i]["file"]).unlink(missing_ok=True)
                log(f"Удалён из карантина: {items[i]['original']}")
                items.pop(i)
            except Exception as ex:
                messagebox.showerror(APP_NAME, str(ex))
        quar_save(items)
        self.refresh_quarantine()

    # ── вкладка «Дубликаты» ───────────────────────────────────────────────────
    def _tab_duplicates(self):
        home = Path.home()
        self.dup_dirs = [str(p) for p in (home / "Downloads", home / "Desktop", home / "Documents") if p.exists()]
        self.dup_groups = []
        self.dup_running = False
        self.dup_stop = threading.Event()

        r1 = ttk.Frame(self.tab_dup)
        r1.pack(fill="x", pady=(12, 0), padx=2)
        ttk.Label(r1, text="Где искать:").pack(side="left")
        self.dup_dirs_lbl = ttk.Label(r1, text="", style="Muted.TLabel")
        self.dup_dirs_lbl.pack(side="left", padx=8)
        ttk.Button(r1, text="Сбросить", command=self._dup_reset_dirs).pack(side="right", padx=(6, 0))
        ttk.Button(r1, text="Добавить папку…", command=self._dup_add_dir).pack(side="right")
        self._dup_show_dirs()

        r2 = ttk.Frame(self.tab_dup)
        r2.pack(fill="x", pady=(10, 0), padx=2)
        self.dup_mode = tk.StringVar(value="similar")
        ttk.Radiobutton(r2, text="Копии и старые версии (файл (1), «— копия»)", value="similar",
                        variable=self.dup_mode).pack(side="left")
        ttk.Radiobutton(r2, text="Точные копии (одинаковое содержимое)", value="exact",
                        variable=self.dup_mode).pack(side="left", padx=14)
        ttk.Label(r2, text="Оставлять:").pack(side="left", padx=(10, 4))
        self.dup_keep = tk.StringVar(value="самый новый")
        cb = ttk.Combobox(r2, textvariable=self.dup_keep, values=["самый новый", "самый старый"], width=13, state="readonly")
        cb.pack(side="left")
        cb.bind("<<ComboboxSelected>>", lambda e: (self._dup_auto_mark(), self._dup_render()))
        self.dup_btn_stop = ttk.Button(r2, text="Стоп", command=self.dup_stop.set, state="disabled")
        self.dup_btn_stop.pack(side="right", padx=(6, 0))
        ttk.Button(r2, text="Найти дубликаты", style="Accent.TButton", command=self.start_dup_scan).pack(side="right")

        r3 = ttk.Frame(self.tab_dup)
        r3.pack(fill="x", pady=(10, 0), padx=2)
        self.dup_info = ttk.Label(r3, text="Нажмите «Найти дубликаты». Лишние копии будут отмечены сами — "
                                          "остаётся только нажать «Удалить отмеченные». Всё уходит в Корзину.",
                                  style="Muted.TLabel")
        self.dup_info.pack(anchor="w")
        self.dup_bar = ttk.Progressbar(r3, mode="determinate")
        self.dup_bar.pack(fill="x", pady=(6, 0))

        r4 = ttk.Frame(self.tab_dup)
        r4.pack(fill="x", pady=(10, 0), padx=2)
        self.dup_sum = ttk.Label(r4, text="", font=(FONT, 10, "bold"))
        self.dup_sum.pack(side="left")
        ttk.Button(r4, text="Удалить отмеченные (в Корзину)", style="Danger.TButton",
                   command=self.dup_delete).pack(side="right", padx=(6, 0))
        ttk.Button(r4, text="Открыть папку", command=self._dup_open).pack(side="right", padx=(6, 0))
        ttk.Button(r4, text="Снять все", command=lambda: self._dup_mark_all(False)).pack(side="right", padx=(6, 0))
        ttk.Button(r4, text="Отметить лишние", command=lambda: (self._dup_auto_mark(), self._dup_render())).pack(side="right", padx=(6, 0))

        wrap = ttk.Frame(self.tab_dup)
        wrap.pack(fill="both", expand=True, padx=2, pady=(6, 0))
        t = ttk.Treeview(wrap, columns=("mark", "size", "date", "path"), show="tree headings", selectmode="browse")
        vs = ttk.Scrollbar(wrap, orient="vertical", command=t.yview)
        t.configure(yscrollcommand=vs.set)
        t.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")
        t.heading("#0", text="Файл")
        t.heading("mark", text="Удалить?")
        t.heading("size", text="Размер, МБ")
        t.heading("date", text="Изменён")
        t.heading("path", text="Папка")
        t.column("#0", width=300)
        t.column("mark", width=90, anchor="center", stretch=False)
        t.column("size", width=100, anchor="e", stretch=False)
        t.column("date", width=135, stretch=False)
        t.column("path", width=480)
        t.tag_configure("group", background=C["panel2"], foreground=C["accent"], font=(FONT, 10, "bold"))
        t.tag_configure("del", background=C["row_danger"], foreground="#ffd0d3")
        t.tag_configure("keep", background=C["panel"], foreground=C["ok"])
        t.bind("<Button-1>", self._dup_click)
        t.bind("<space>", lambda e: self._dup_toggle(t.focus()))
        self.tree_dup = t

    def _dup_show_dirs(self):
        txt = " · ".join(self.dup_dirs) if self.dup_dirs else "папки не выбраны"
        self.dup_dirs_lbl.config(text=txt if len(txt) < 140 else txt[:137] + "…")

    def _dup_add_dir(self):
        d = filedialog.askdirectory(title="Папка для поиска дубликатов")
        if d and d not in self.dup_dirs:
            self.dup_dirs.append(os.path.normpath(d))
            self._dup_show_dirs()

    def _dup_reset_dirs(self):
        self.dup_dirs = []
        self._dup_show_dirs()

    def start_dup_scan(self):
        if self.dup_running:
            return
        if not self.dup_dirs:
            messagebox.showinfo(APP_NAME, "Добавьте хотя бы одну папку.")
            return
        self.dup_running = True
        self.dup_stop.clear()
        self.dup_btn_stop.state(["!disabled"])
        self.tree_dup.delete(*self.tree_dup.get_children())
        self.dup_sum.config(text="")
        threading.Thread(target=self._dup_worker, args=(list(self.dup_dirs), self.dup_mode.get()), daemon=True).start()

    def _dup_worker(self, dirs, mode):
        post = lambda *a: self.q.put(a)
        groups = []
        try:
            groups = self._dup_find_similar(dirs, post) if mode == "similar" else self._dup_find_exact(dirs, post)
        except Exception as ex:
            post("dup_info", f"Ошибка: {ex}")
        post("dup_done", groups, mode)

    def _walk(self, dirs):
        seen = set()
        for top in dirs:
            for root, subdirs, files in os.walk(top):
                if self.dup_stop.is_set():
                    return
                subdirs[:] = [d for d in subdirs if d.lower() not in DUP_SKIP_DIRS and not d.startswith(".")]
                real = os.path.normcase(os.path.realpath(root))
                if real in seen:
                    subdirs[:] = []
                    continue
                seen.add(real)
                yield root, subdirs, files

    @staticmethod
    def _entry(path, is_dir=False):
        st = os.stat(path)
        return {"path": path, "size": dir_size(path) if is_dir else st.st_size, "mtime": st.st_mtime,
                "dir": is_dir, "mark": False}

    def _dup_find_similar(self, dirs, post):
        post("dup_info", "Ищу копии и старые версии…")
        buckets = {}
        n = 0
        for root, subdirs, files in self._walk(dirs):
            for name in files:
                key = (os.path.normcase(root), norm_name(name))
                buckets.setdefault(key, []).append((os.path.join(root, name), False, name))
            for name in subdirs:
                key = (os.path.normcase(root), "<dir>" + norm_name(name, True))
                buckets.setdefault(key, []).append((os.path.join(root, name), True, name))
            n += 1
            if n % 200 == 0:
                post("dup_info", f"Просмотрено папок: {n}… {root}")
        groups = []
        for key, items in buckets.items():
            if len(items) < 2:
                continue
            # в группе должен быть хотя бы один файл-копия (с «(1)», «копия» и т.п.)
            if all(norm_name(nm, d) == nm.lower() for _, d, nm in items):
                continue
            try:
                groups.append([self._entry(p, d) for p, d, _ in items])
            except OSError:
                pass
        # вложенные копии внутри уже найденных папок-копий не дублируем
        return groups

    def _dup_find_exact(self, dirs, post):
        post("dup_info", "Собираю список файлов…")
        by_size = {}
        count = 0
        for root, _, files in self._walk(dirs):
            for name in files:
                p = os.path.join(root, name)
                try:
                    sz = os.path.getsize(p)
                except OSError:
                    continue
                if sz >= 1024:
                    by_size.setdefault(sz, []).append(p)
                    count += 1
        cands = [ps for ps in by_size.values() if len(ps) > 1]
        total = sum(len(x) for x in cands)
        done = 0
        groups = []
        post("dup_info", f"Файлов: {count}. Сравниваю содержимое {total} кандидатов…")
        for paths in cands:
            if self.dup_stop.is_set():
                break
            part = {}
            for p in paths:
                try:
                    part.setdefault(_partial_hash(p), []).append(p)
                except OSError:
                    pass
                done += 1
            post("dup_progress", done, total)
            for same in part.values():
                if len(same) < 2:
                    continue
                full = {}
                for p in same:
                    try:
                        full.setdefault(_full_hash(p), []).append(p)
                    except OSError:
                        pass
                for g in full.values():
                    if len(g) > 1:
                        try:
                            groups.append([self._entry(p) for p in g])
                        except OSError:
                            pass
        return groups

    def _dup_finished(self, groups, mode):
        self.dup_running = False
        self.dup_btn_stop.state(["disabled"])
        self.dup_bar.config(value=self.dup_bar["maximum"])
        groups.sort(key=lambda g: -sum(e["size"] for e in g))
        self.dup_groups = groups
        self._dup_auto_mark()
        self._dup_render()
        kind = "групп копий/версий" if mode == "similar" else "групп одинаковых файлов"
        self.dup_info.config(text=f"Найдено {kind}: {len(groups)}. Красным отмечено то, что будет удалено, "
                                  f"зелёным — что останется. Щёлкните по строке, чтобы поменять.")

    def _dup_auto_mark(self):
        newest = self.dup_keep.get() == "самый новый"
        for g in self.dup_groups:
            keep = max(g, key=lambda e: e["mtime"]) if newest else min(g, key=lambda e: e["mtime"])
            for e in g:
                e["mark"] = e is not keep

    def _dup_mark_all(self, value):
        for g in self.dup_groups:
            for e in g:
                e["mark"] = value
        self._dup_render()

    def _dup_render(self):
        t = self.tree_dup
        opened = {i for i in t.get_children() if t.item(i, "open")}
        t.delete(*t.get_children())
        n_del, sz_del = 0, 0
        for gi, g in enumerate(self.dup_groups):
            gid = f"g{gi}"
            name = os.path.basename(g[0]["path"])
            gsize = sum(e["size"] for e in g)
            t.insert("", "end", iid=gid, text=f"{name}  ·  {len(g)} шт.", values=("", fmt_mb(gsize), "", ""),
                     tags=("group",), open=(gid in opened or len(self.dup_groups) <= 60))
            for ei, e in enumerate(g):
                if e["mark"]:
                    n_del += 1
                    sz_del += e["size"]
                label = os.path.basename(e["path"]) + (" (папка)" if e["dir"] else "")
                t.insert(gid, "end", iid=f"{gid}_{ei}", text=label,
                         values=("☒ удалить" if e["mark"] else "☐ оставить", fmt_mb(e["size"]),
                                 datetime.datetime.fromtimestamp(e["mtime"]).strftime("%d.%m.%Y %H:%M"),
                                 os.path.dirname(e["path"])),
                         tags=("del" if e["mark"] else "keep",))
        self.dup_sum.config(text=f"Отмечено к удалению: {n_del}  ·  освободится {fmt_mb(sz_del)} МБ" if self.dup_groups else "")

    def _dup_entry(self, iid):
        m = re.fullmatch(r"g(\d+)_(\d+)", iid or "")
        if not m:
            return None
        gi, ei = int(m.group(1)), int(m.group(2))
        try:
            return self.dup_groups[gi][ei]
        except IndexError:
            return None

    def _dup_click(self, event):
        iid = self.tree_dup.identify_row(event.y)
        if self.tree_dup.identify_column(event.x) == "#1" and iid:
            self._dup_toggle(iid)
            return "break"

    def _dup_toggle(self, iid):
        e = self._dup_entry(iid)
        if e:
            e["mark"] = not e["mark"]
            y = self.tree_dup.yview()
            self._dup_render()
            self.tree_dup.yview_moveto(y[0])
            if self.tree_dup.exists(iid):
                self.tree_dup.selection_set(iid)

    def _dup_open(self):
        e = self._dup_entry(self.tree_dup.focus())
        if e:
            open_in_explorer(e["path"])

    def dup_delete(self):
        marked = [(g, e) for g in self.dup_groups for e in g if e["mark"]]
        if not marked:
            messagebox.showinfo(APP_NAME, "Ничего не отмечено.")
            return
        full = [g for g in self.dup_groups if all(e["mark"] for e in g)]
        if full and not messagebox.askyesno(APP_NAME, f"В {len(full)} групп(ах) отмечены ВСЕ копии — "
                                                      "от этих файлов не останется ни одной.\n\nВсё равно удалить?"):
            return
        size = sum(e["size"] for _, e in marked)
        if not messagebox.askyesno(APP_NAME, f"Удалить {len(marked)} шт. ({fmt_mb(size)} МБ)?\n\n"
                                             "Всё уйдёт в Корзину — при ошибке можно восстановить."):
            return
        ok, errors = 0, []
        for g, e in marked:
            try:
                if to_recycle_bin(e["path"]):
                    ok += 1
                    g.remove(e)
                    log(f"Дубликат удалён в корзину: {e['path']}")
                else:
                    errors.append(e["path"])
            except Exception as ex:
                errors.append(f"{e['path']}: {ex}")
        self.dup_groups = [g for g in self.dup_groups if len(g) > 1]
        self._dup_render()
        self.set_status(f"Удалено в Корзину: {ok}, освобождено {fmt_mb(size)} МБ", C["ok"])
        if errors:
            messagebox.showwarning(APP_NAME, "Не удалось удалить (файл открыт или нет прав):\n\n" + "\n".join(errors[:15]))

    # ── вкладка «Настройки» ───────────────────────────────────────────────────
    def _tab_settings(self):
        f = ttk.Frame(self.tab_set)
        f.pack(fill="both", expand=True, padx=8, pady=16)

        ttk.Label(f, text="VirusTotal API-ключ", font=(FONT, 11, "bold")).grid(row=0, column=0, sticky="w")
        ttk.Label(f, style="Muted.TLabel",
                  text="Бесплатно: зарегистрируйтесь на virustotal.com → профиль → API Key. "
                       "Программа отправляет туда только хэш файла, а не сам файл.").grid(row=1, column=0, columnspan=3, sticky="w")
        self.vt_var = tk.StringVar(value=self.cfg.get("vt_key", ""))
        self.vt_entry = ttk.Entry(f, textvariable=self.vt_var, width=70, show="•")
        self.vt_entry.grid(row=2, column=0, sticky="w", pady=(6, 0))
        self.show_key = tk.BooleanVar()
        ttk.Checkbutton(f, text="Показать", variable=self.show_key,
                        command=lambda: self.vt_entry.config(show="" if self.show_key.get() else "•")).grid(row=2, column=1, padx=8, sticky="w")

        ttk.Label(f, text="Частота обновления (секунд)", font=(FONT, 11, "bold")).grid(row=3, column=0, sticky="w", pady=(22, 0))
        self.int_var = tk.StringVar(value=str(self.cfg.get("interval", 2)))
        ttk.Spinbox(f, from_=1, to=10, textvariable=self.int_var, width=6).grid(row=4, column=0, sticky="w", pady=(6, 0))

        self.notify_var = tk.BooleanVar(value=self.cfg.get("notify", True))
        ttk.Checkbutton(f, text="Предупреждать окном, если появился опасный процесс", variable=self.notify_var).grid(
            row=5, column=0, sticky="w", pady=(22, 0))

        self.tray_var = tk.BooleanVar(value=self.cfg.get("to_tray", True))
        ttk.Checkbutton(f, text="При закрытии окна сворачиваться в трей (работать в фоне)", variable=self.tray_var).grid(
            row=6, column=0, sticky="w", pady=(10, 0))
        self.auto_var = tk.BooleanVar(value=autostart_enabled())
        cb = ttk.Checkbutton(f, text="Запускать вместе с Windows (сразу с правами администратора)", variable=self.auto_var)
        cb.grid(row=7, column=0, sticky="w", pady=(10, 0))
        if not (IS_WIN and is_admin()):
            cb.state(["disabled"])

        ttk.Button(f, text="Сохранить", style="Accent.TButton", command=self.save_settings).grid(row=8, column=0, sticky="w", pady=(22, 0))

        info = (f"Встроенный антивирус: {engine_name() or 'не найден'}\n"
                f"Права: {'администратор' if is_admin() else 'обычный пользователь — часть процессов скрыта'}\n"
                f"Папка программы: {DATA_DIR}\n"
                f"Журнал действий: {LOG_FILE}\n\n"
                "Проверка работы: создайте текстовый файл с тестовой строкой EICAR (её легко найти в интернете,\n"
                "это безопасный «учебный вирус») и проверьте его во вкладке «Сканер».")
        ttk.Label(f, text=info, style="Muted.TLabel", justify="left").grid(row=9, column=0, columnspan=3, sticky="w", pady=(30, 0))

        ttk.Label(f, text=f"Обновления · версия {APP_VERSION}", font=(FONT, 11, "bold")).grid(row=10, column=0, sticky="w", pady=(26, 0))
        self.autoupd_var = tk.BooleanVar(value=self.cfg.get("auto_update", True))
        ttk.Checkbutton(f, text="Обновляться автоматически (программа и база угроз, раз в 6 часов)",
                        variable=self.autoupd_var).grid(row=11, column=0, sticky="w", pady=(6, 0))
        ub = ttk.Frame(f)
        ub.grid(row=12, column=0, columnspan=3, sticky="w", pady=(8, 0))
        ttk.Button(ub, text="Проверить обновления", command=lambda: self.check_updates(manual=True)).pack(side="left")
        self.upd_label = ttk.Label(ub, text=f"Источник: github.com/{UPDATE_REPO}", style="Muted.TLabel")
        self.upd_label.pack(side="left", padx=12)

    def save_settings(self):
        try:
            iv = max(1, min(10, int(float(self.int_var.get()))))
        except ValueError:
            iv = 2
        self.cfg.update({"vt_key": self.vt_var.get().strip(), "interval": iv, "notify": self.notify_var.get(),
                         "to_tray": self.tray_var.get(), "auto_update": self.autoupd_var.get()})
        if IS_WIN and is_admin() and self.auto_var.get() != autostart_enabled():
            ok, err = set_autostart(self.auto_var.get())
            if not ok:
                messagebox.showerror(APP_NAME, f"Не удалось изменить автозапуск:\n{err}")
        save_config(self.cfg)
        self.sampler.cfg = self.cfg
        if self.cfg["vt_key"]:
            self.use_vt.set(True)
        self.set_status("Настройки сохранены", C["ok"])

    # ── главный цикл обновления ───────────────────────────────────────────────
    def _poll(self):
        latest = None
        try:
            while True:
                msg = self.q.get_nowait()
                kind = msg[0]
                if kind == "snapshot":
                    latest = msg[1]
                elif kind == "error":
                    self.set_status("Ошибка мониторинга: " + msg[1], C["danger"])
                elif kind == "scan_info":
                    self.scan_info.config(text=msg[1])
                elif kind == "scan_max":
                    self.scan_bar.config(maximum=msg[1], value=0)
                elif kind == "scan_progress":
                    self.scan_bar.config(value=msg[1])
                elif kind == "scan_result":
                    _, path, lvl, reasons, digest = msg
                    self._scan_add(path, lvl, reasons, digest)
                elif kind == "scan_engine_hit":
                    self._scan_add(msg[1], "danger", [msg[2]])
                elif kind == "scan_engine_clean":
                    self._scan_add(msg[1], "ok", [msg[2]])
                elif kind == "scan_engine_err":
                    self.set_status(msg[1], C["warn"])
                elif kind == "call":
                    try:
                        msg[1]()
                    except Exception:
                        pass
                elif kind == "dup_info":
                    self.dup_info.config(text=msg[1])
                elif kind == "dup_progress":
                    self.dup_bar.config(maximum=max(msg[2], 1), value=msg[1])
                elif kind == "dup_done":
                    self._dup_finished(msg[1], msg[2])
                elif kind == "scan_done":
                    self._scan_finished(*msg[1:])
        except queue.Empty:
            pass
        if SHOW_FLAG.exists():
            try:
                SHOW_FLAG.unlink()
            except Exception:
                pass
            self.show_window()
        if latest:
            self._apply_snapshot(latest)
        if self.scan_running:
            self.render_scan()
        self.after(250, self._poll)

    def _scan_finished(self, total, found, took, stopped):
        self.scan_running = False
        self.btn_stop.state(["disabled"])
        self.scan_bar.config(value=self.scan_bar["maximum"])
        self.render_scan()
        head = "Проверка остановлена" if stopped else "Проверка завершена"
        text = f"{head}: файлов {total}, найдено угроз и подозрений: {found}, время {took:.0f} с"
        self.scan_info.config(text=text)
        self.set_status(text, C["danger"] if found else C["ok"])
        log(text)
        if found and not stopped:
            messagebox.showwarning(APP_NAME, f"Найдено подозрительных файлов: {found}.\n\nВыберите их в списке и нажмите «В карантин».")

    def _apply_snapshot(self, snap):
        self.snapshot = snap
        self.rows_by_pid = {r["pid"]: r for r in snap["rows"]}
        self.card_cpu.set(f"{snap['cpu']:.0f}%", f"{psutil.cpu_count()} потоков", snap["cpu"])
        self.card_ram.set(f"{snap['ram']:.0f}%", f"{fmt_gb(snap['ram_used'])} из {fmt_gb(snap['ram_total'])} ГБ", snap["ram"])
        self.card_disk.set(f"{snap['disk']:.0f}%", "занято", snap["disk"])
        self.card_proc.set(str(len(snap["rows"])), "активно сейчас", None)

        self.render_processes()
        self.render_apps()
        n_d, n_w = self.render_threats()
        if n_d:
            self.card_threat.set(str(n_d + n_w), f"опасных: {n_d}", None, C["danger"])
            self.shield.config(text="Обнаружены угрозы!", fg=C["danger"])
            self.tray.set_title(f"Страж — угроз: {n_d + n_w}")
        elif n_w:
            self.card_threat.set(str(n_w), "подозрительных", None, C["warn"])
            self.shield.config(text="Есть подозрительные процессы", fg=C["warn"])
        else:
            self.card_threat.set("0", "всё чисто", None, C["ok"])
            self.shield.config(text="Защита активна", fg=C["ok"])
            self.tray.set_title("Страж — защита активна")

        new_danger = [r for r in snap["rows"] if r["level"] == "danger" and (r["pid"], r["exe"]) not in self.alerted]
        for r in new_danger:
            self.alerted.add((r["pid"], r["exe"]))
            log(f"Опасный процесс: {r['name']} PID {r['pid']} {r['exe']} — {'; '.join(r['reasons'])}")
        if new_danger and self.cfg.get("notify", True) and self.state() == "withdrawn":
            r = new_danger[0]
            self.tray.notify(f"Опасный процесс: {r['name']}\n{(r['reasons'] or [''])[0]}", "Страж — угроза!")
        elif new_danger and self.cfg.get("notify", True):
            r = new_danger[0]
            self.bell()
            if messagebox.askyesno(APP_NAME, f"Обнаружен опасный процесс!\n\n{r['name']} (PID {r['pid']})\n{r['exe']}\n\n"
                                             + "\n".join("• " + x for x in r["reasons"]) + "\n\nОткрыть вкладку «Угрозы»?"):
                self.nb.select(self.tab_threat)
        if not self.scan_running:
            self.set_status(f"Обновлено {datetime.datetime.now():%H:%M:%S} · процессов: {len(snap['rows'])} · "
                            f"двойной щелчок по строке — подробности, правая кнопка — действия")

    def _on_close(self):
        if self.tray.icon and self.cfg.get("to_tray", True):
            self.hide_window()
        else:
            self.quit_app()


def relaunch_as_admin():
    """Перезапускает программу с правами администратора (появится окно UAC «Да/Нет»)."""
    import ctypes
    exe, args = app_command()
    extra = " ".join(f'"{a}"' for a in sys.argv[1:])
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, f"{args} {extra}".strip(), None, 1)
    return rc > 32


def already_running():
    """Не даём запустить две копии: вторая просто показывает окно первой."""
    if IS_WIN:
        import ctypes
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        global _MUTEX
        _MUTEX = k32.CreateMutexW(None, False, "Local\\StrazhSingleInstance")
        if ctypes.get_last_error() == 183:  # ERROR_ALREADY_EXISTS
            ensure_dirs()
            SHOW_FLAG.write_text("1")
            return True
    return False


def main():
    if IS_WIN:
        import ctypes
        if not is_admin() and "--no-admin" not in sys.argv:
            if relaunch_as_admin():
                return
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)  # чёткий шрифт на экранах с масштабированием
        except Exception:
            pass
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("Strazh.Antivirus")
        except Exception:
            pass
    if already_running():
        return
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
