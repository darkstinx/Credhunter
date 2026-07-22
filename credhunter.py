#!/usr/bin/env python3
"""
credhunter - scans Linux home directories for exposed credentials.

Categories: ssh_keys, cloud_credentials, browser_credentials,
shell_history, keyrings, git_tokens, app_credentials.

Usage:
    python3 credhunter.py                      # scan current user's home
    python3 credhunter.py --all-users          # scan /home/* (needs root)
    python3 credhunter.py --path /home/user1   # scan specific path(s)
    python3 credhunter.py --json -o report.json
    python3 credhunter.py --min-severity HIGH --redact
"""

import argparse
import base64
import json
import os
import re
import sqlite3
import stat
import sys
import tempfile
import time
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Optional

try:
    import pwd
except ImportError:
    pwd = None

try:
    import colorama
    colorama.init()
    HAVE_COLORAMA = True
except ImportError:
    HAVE_COLORAMA = False

# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

COLORS = {
    "CRITICAL": "\033[1;97;41m",
    "HIGH": "\033[1;31m",
    "MEDIUM": "\033[1;33m",
    "LOW": "\033[1;36m",
    "INFO": "\033[1;34m",
    "BOLD": "\033[1m",
    "DIM": "\033[2m",
    "GREEN": "\033[1;32m",
    "RESET": "\033[0m",
}

CATEGORIES = [
    "ssh_keys",
    "cloud_credentials",
    "browser_credentials",
    "shell_history",
    "keyrings",
    "git_tokens",
    "app_credentials",
]

MAX_FILE_BYTES = 1_000_000          # skip reading files larger than this
MAX_WALK_FILES = 50_000             # hard cap on files visited during recursive walk
MAX_WALK_DEPTH = 8                  # recursion depth for app_credentials walk
EXCLUDED_DIR_NAMES = {
    ".cache", "node_modules", "__pycache__", "venv", ".venv", "site-packages",
    ".npm", ".cargo", ".rustup", "snap", ".local/share/Trash", ".git",
    ".mozilla/firefox", "vendor", ".gradle", ".m2", ".nuget", "target",
    "dist", "build",
}
INTERESTING_APP_FILES = {
    ".env", "config.php", "wp-config.php", "settings.py", "database.yml",
    "secrets.yml", "secrets.yaml", "appsettings.json", ".htpasswd",
    "docker-compose.yml", "docker-compose.yaml", "credentials.xml",
    "sitemanager.xml", ".my.cnf", ".pgpass",
}
INTERESTING_APP_PREFIXES = (".env.", "appsettings.")

PLACEHOLDER_VALUES = {
    "changeme", "change_me", "xxxxx", "placeholder", "your_password_here",
    "password", "<password>", "***", "null", "none", "", "example",
    "insert_here", "todo", "secret", "yourpassword", "REPLACE_ME".lower(),
}

SECRET_KEY_RE = re.compile(
    r'(?im)^[^\S\r\n]*[\'"]?(?P<key>[A-Za-z0-9_.\-]*'
    r'(?:pass(?:word)?|secret|token|api[_-]?key|access[_-]?key|'
    r'private[_-]?key|client[_-]?secret|db[_-]?pass|auth)[A-Za-z0-9_.\-]*)'
    r'[\'"]?[^\S\r\n]*[:=][^\S\r\n]*[\'"]?(?P<value>[^\s\'"#;]{3,200})[\'"]?'
)

HISTORY_PATTERNS = [
    ("curl_basic_auth", re.compile(r'curl\s+.*-u\s*[\'"]?[^\s\'"]+:[^\s\'"]+')),
    ("mysql_inline_pw", re.compile(r'mysql\s+.*-p\S+')),
    ("sshpass", re.compile(r'sshpass\s+-p\s*\S+')),
    ("pgpassword_env", re.compile(r'PGPASSWORD=\S+')),
    ("bearer_token", re.compile(r'Authorization:\s*Bearer\s+\S+', re.I)),
    ("aws_secret_env", re.compile(r'AWS_(?:SECRET_ACCESS_KEY|ACCESS_KEY_ID)=\S+')),
    ("wget_auth", re.compile(r'wget\s+.*--(?:http|ftp)-password=\S+')),
    ("private_key_block", re.compile(r'-----BEGIN[ A-Z]*PRIVATE KEY-----')),
    ("export_secret", SECRET_KEY_RE),
]

RECOMMENDATIONS = {
    "ssh_keys": "Protect the key with a passphrase, chmod 600 it, and rotate it if it was ever exposed.",
    "cloud_credentials": "Revoke/rotate the credential in the provider console and use a secrets manager or short-lived tokens instead.",
    "browser_credentials": "Migrate saved logins to a dedicated password manager and clear the browser's stored credentials.",
    "shell_history": "Avoid passing secrets on the command line; use env files, prompts, or credential helpers, then purge history (HISTCONTROL=ignorespace).",
    "keyrings": "Ensure the keyring is not auto-unlocked with the login password; set a distinct keyring passphrase.",
    "git_tokens": "Revoke the token from the provider, switch to a credential manager, and remove plaintext token files.",
    "app_credentials": "Move secrets out of source/config files into environment variables or a secrets manager, and add the file to .gitignore.",
}

# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------


@dataclass
class Finding:
    category: str
    subtype: str
    title: str
    path: str
    severity: str
    owner: str
    permissions: str
    world_readable: bool
    group_readable: bool
    value: Optional[str]
    notes: str
    recommendation: str = ""

    def __post_init__(self):
        if not self.recommendation:
            self.recommendation = RECOMMENDATIONS.get(self.category, "")


@dataclass
class Stats:
    permission_errors: int = 0
    files_scanned: int = 0
    walk_truncated: bool = False


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def owner_name(uid: int) -> str:
    if pwd is None:
        return str(uid)
    try:
        return pwd.getpwuid(uid).pw_name
    except Exception:
        return str(uid)


def file_meta(path: Path, stats: Stats):
    try:
        st = path.stat()
    except OSError:
        stats.permission_errors += 1
        return None
    mode = stat.S_IMODE(st.st_mode)
    return {
        "perms": oct(mode)[2:].zfill(3),
        "world_readable": bool(mode & stat.S_IROTH),
        "group_readable": bool(mode & stat.S_IRGRP),
        "owner": owner_name(st.st_uid),
        "size": st.st_size,
    }


def bump(sev: str, levels: int = 1) -> str:
    i = SEVERITY_ORDER.index(sev)
    return SEVERITY_ORDER[min(i + levels, len(SEVERITY_ORDER) - 1)]


def classify(base_severity: str, meta: dict) -> str:
    if meta["world_readable"]:
        return "CRITICAL"
    if meta["group_readable"]:
        return bump(base_severity, 1)
    return base_severity


def reveal(value: Optional[str], redact: bool) -> Optional[str]:
    if value is None:
        return None
    if not redact:
        return value
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "..." + value[-4:]


def is_probably_binary(chunk: bytes) -> bool:
    return b"\x00" in chunk


def safe_read_text(path: Path, stats: Stats, max_bytes: int = MAX_FILE_BYTES) -> Optional[str]:
    try:
        if path.stat().st_size > max_bytes:
            return None
        with open(path, "rb") as fh:
            raw = fh.read(max_bytes)
    except (OSError, PermissionError):
        stats.permission_errors += 1
        return None
    if is_probably_binary(raw[:2048]):
        return None
    try:
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return None


def is_placeholder(value: str) -> bool:
    v = value.strip().strip("'\"").lower()
    if v in PLACEHOLDER_VALUES:
        return True
    if v.startswith("$") or v.startswith("%") or v.startswith("<"):
        return True
    if set(v) == {"*"} or set(v) == {"x"}:
        return True
    return False


def make_finding(category, subtype, title, path, base_severity, meta, value,
                  notes, redact) -> Finding:
    return Finding(
        category=category,
        subtype=subtype,
        title=title,
        path=str(path),
        severity=classify(base_severity, meta),
        owner=meta["owner"],
        permissions=meta["perms"],
        world_readable=meta["world_readable"],
        group_readable=meta["group_readable"],
        value=reveal(value, redact),
        notes=notes,
    )


# --------------------------------------------------------------------------
# Category scanners
# --------------------------------------------------------------------------


def scan_ssh_keys(home: Path, args, stats: Stats):
    findings = []
    ssh_dir = home / ".ssh"
    if not ssh_dir.is_dir():
        return findings
    try:
        candidates = list(ssh_dir.iterdir())
    except (OSError, PermissionError):
        stats.permission_errors += 1
        return findings

    for f in candidates:
        if not f.is_file() or f.suffix == ".pub":
            continue
        text = safe_read_text(f, stats, max_bytes=200_000)
        if not text or "-----BEGIN" not in text or "PRIVATE KEY" not in text:
            continue
        meta = file_meta(f, stats)
        if meta is None:
            continue
        encrypted = "ENCRYPTED" in text or "Proc-Type: 4,ENCRYPTED" in text
        base_sev = "LOW" if encrypted else "HIGH"
        notes = (
            "Passphrase-protected private key." if encrypted
            else "Private key has NO passphrase - directly usable for authentication."
        )
        findings.append(make_finding(
            "ssh_keys", "private_key", f"SSH private key ({f.name})", f,
            base_sev, meta, text if not encrypted else None, notes, args.redact,
        ))
    return findings


def scan_cloud_credentials(home: Path, args, stats: Stats):
    findings = []

    aws_creds = home / ".aws" / "credentials"
    if aws_creds.is_file():
        text = safe_read_text(aws_creds, stats)
        meta = file_meta(aws_creds, stats)
        if text and meta:
            profile = None
            for line in text.splitlines():
                line = line.strip()
                if line.startswith("[") and line.endswith("]"):
                    profile = line.strip("[]")
                elif "=" in line and profile:
                    key, _, val = line.partition("=")
                    key, val = key.strip().lower(), val.strip()
                    if key in ("aws_access_key_id", "aws_secret_access_key", "aws_session_token") and val:
                        findings.append(make_finding(
                            "cloud_credentials", "aws", f"AWS {key} (profile {profile})",
                            aws_creds, "HIGH", meta, val,
                            "Plaintext AWS credential file.", args.redact,
                        ))

    gcp_paths = [
        home / ".config" / "gcloud" / "application_default_credentials.json",
    ]
    gcp_legacy_dir = home / ".config" / "gcloud" / "legacy_credentials"
    if gcp_legacy_dir.is_dir():
        try:
            for sub in gcp_legacy_dir.iterdir():
                gcp_paths.append(sub / "adc.json")
        except (OSError, PermissionError):
            stats.permission_errors += 1
    for gp in gcp_paths:
        if gp.is_file():
            text = safe_read_text(gp, stats)
            meta = file_meta(gp, stats)
            if text and meta:
                findings.append(make_finding(
                    "cloud_credentials", "gcp", f"GCP application default credentials ({gp.name})",
                    gp, "HIGH", meta, text, "Contains OAuth client secret/refresh token for GCP.",
                    args.redact,
                ))

    azure_tokens = home / ".azure" / "accessTokens.json"
    if azure_tokens.is_file():
        text = safe_read_text(azure_tokens, stats)
        meta = file_meta(azure_tokens, stats)
        if text and meta:
            findings.append(make_finding(
                "cloud_credentials", "azure", "Azure CLI cached access/refresh tokens",
                azure_tokens, "CRITICAL", meta, text,
                "Contains live Azure AD access and refresh tokens.", args.redact,
            ))

    kube_cfg = home / ".kube" / "config"
    if kube_cfg.is_file():
        text = safe_read_text(kube_cfg, stats)
        meta = file_meta(kube_cfg, stats)
        if text and meta and ("token:" in text or "client-key-data:" in text or "password:" in text):
            findings.append(make_finding(
                "cloud_credentials", "kubernetes", "Kubeconfig with embedded credentials",
                kube_cfg, "HIGH", meta, text,
                "kubeconfig contains an auth token or client key material.", args.redact,
            ))

    docker_cfg = home / ".docker" / "config.json"
    if docker_cfg.is_file():
        text = safe_read_text(docker_cfg, stats)
        meta = file_meta(docker_cfg, stats)
        if text and meta:
            try:
                data = json.loads(text)
                for registry, entry in data.get("auths", {}).items():
                    auth_b64 = entry.get("auth")
                    if not auth_b64:
                        continue
                    try:
                        decoded = base64.b64decode(auth_b64).decode("utf-8", "replace")
                    except Exception:
                        decoded = auth_b64
                    findings.append(make_finding(
                        "cloud_credentials", "docker", f"Docker registry credential ({registry})",
                        docker_cfg, "HIGH", meta, decoded,
                        "Base64-decoded docker registry auth (user:password or token).", args.redact,
                    ))
            except json.JSONDecodeError:
                pass

    tf_creds = home / ".terraform.d" / "credentials.tfrc.json"
    if tf_creds.is_file():
        text = safe_read_text(tf_creds, stats)
        meta = file_meta(tf_creds, stats)
        if text and meta:
            findings.append(make_finding(
                "cloud_credentials", "terraform", "Terraform Cloud/Enterprise API token",
                tf_creds, "HIGH", meta, text, "Plaintext Terraform API token file.", args.redact,
            ))

    return findings


def _find_sqlite_logins(db_path: Path, stats: Stats):
    rows = []
    try:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_copy = Path(tmp) / "copy.sqlite"
            tmp_copy.write_bytes(db_path.read_bytes())
            conn = sqlite3.connect(str(tmp_copy))
            cur = conn.cursor()
            cur.execute("SELECT origin_url, username_value, password_value FROM logins")
            rows = cur.fetchall()
            conn.close()
    except Exception:
        pass
    return rows


def scan_browser_credentials(home: Path, args, stats: Stats):
    findings = []

    chrome_profiles = [
        home / ".config" / "google-chrome",
        home / ".config" / "chromium",
        home / ".config" / "BraveSoftware" / "Brave-Browser",
        home / ".config" / "microsoft-edge",
    ]
    for browser_dir in chrome_profiles:
        if not browser_dir.is_dir():
            continue
        try:
            profile_dirs = [p for p in browser_dir.iterdir() if p.is_dir()]
        except (OSError, PermissionError):
            stats.permission_errors += 1
            continue
        for profile in profile_dirs:
            login_db = profile / "Login Data"
            if not login_db.is_file():
                continue
            meta = file_meta(login_db, stats)
            if meta is None:
                continue
            rows = _find_sqlite_logins(login_db, stats)
            if not rows:
                findings.append(make_finding(
                    "browser_credentials", "chromium_store",
                    f"{browser_dir.name} saved-login store ({profile.name})",
                    login_db, "LOW", meta, None,
                    "Login Data database present; could not read rows (locked or empty).",
                    args.redact,
                ))
                continue
            for origin, username, pw_blob in rows[:100]:
                if pw_blob[:3] in (b"v10", b"v11"):
                    sev = "MEDIUM"
                    note = ("Password encrypted with libsecret/kwallet-derived key (v11) or the "
                            "fixed 'peanuts' key used when no OS keyring is available (v10, often "
                            "crackable offline). Origin: %s" % origin)
                    value = None
                else:
                    sev = "CRITICAL"
                    note = f"Password appears to be stored in PLAINTEXT. Origin: {origin}"
                    value = pw_blob.decode("utf-8", "replace")
                findings.append(make_finding(
                    "browser_credentials", "chromium_login",
                    f"{browser_dir.name} saved login for {username or '(unknown user)'}",
                    login_db, sev, meta, value, note, args.redact,
                ))

    firefox_ini = home / ".mozilla" / "firefox" / "profiles.ini"
    if firefox_ini.is_file():
        text = safe_read_text(firefox_ini, stats) or ""
        profile_paths = re.findall(r"^Path=(.+)$", text, re.M)
        for rel in profile_paths:
            prof_dir = (home / ".mozilla" / "firefox" / rel)
            for fname, sev, note in (
                ("logins.json", "MEDIUM", "Encrypted Firefox saved logins (NSS-protected)."),
                ("key4.db", "LOW", "Firefox NSS key database used to decrypt logins.json."),
            ):
                fpath = prof_dir / fname
                if fpath.is_file():
                    meta = file_meta(fpath, stats)
                    if meta:
                        findings.append(make_finding(
                            "browser_credentials", "firefox_store", f"Firefox {fname} ({rel})",
                            fpath, sev, meta, None,
                            note + " Check whether a master password is set before attempting decryption.",
                            args.redact,
                        ))
    return findings


def scan_shell_history(home: Path, args, stats: Stats):
    findings = []
    history_files = [
        ".bash_history", ".zsh_history", ".sh_history", ".ksh_history",
        ".python_history", ".mysql_history", ".psql_history", ".lesshst",
    ]
    seen_lines = set()
    for fname in history_files:
        fpath = home / fname
        if not fpath.is_file():
            continue
        text = safe_read_text(fpath, stats)
        meta = file_meta(fpath, stats)
        if not text or not meta:
            continue
        match_count = 0
        for lineno, raw_line in enumerate(text.splitlines(), start=1):
            line = raw_line.lstrip(": ").split(";", 1)[-1] if fname == ".zsh_history" else raw_line
            for subtype, pattern in HISTORY_PATTERNS:
                m = pattern.search(line)
                if not m:
                    continue
                key = (fname, line.strip())
                if key in seen_lines:
                    continue
                if subtype == "export_secret":
                    val = m.group("value")
                    if is_placeholder(val):
                        continue
                seen_lines.add(key)
                match_count += 1
                findings.append(make_finding(
                    "shell_history", subtype, f"Secret-looking command in {fname} (line {lineno})",
                    fpath, "MEDIUM", meta, line.strip(),
                    "Command history retains what looks like a credential.", args.redact,
                ))
                break
            if match_count >= 50:
                break
    return findings


def scan_keyrings(home: Path, args, stats: Stats):
    findings = []
    keyring_dir = home / ".local" / "share" / "keyrings"
    if keyring_dir.is_dir():
        try:
            entries = list(keyring_dir.iterdir())
        except (OSError, PermissionError):
            stats.permission_errors += 1
            entries = []
        for f in entries:
            if f.suffix != ".keyring":
                continue
            meta = file_meta(f, stats)
            if meta is None:
                continue
            text = safe_read_text(f, stats) or ""
            unlocked_hint = "no lock" in text.lower() if text else False
            findings.append(make_finding(
                "keyrings", "gnome_keyring", f"GNOME keyring file ({f.name})",
                f, "LOW" if not unlocked_hint else "MEDIUM", meta, None,
                "GNOME keyring store. 'login.keyring' is often auto-unlocked with the user's "
                "login password on login.", args.redact,
            ))

    kwallet_dir = home / ".local" / "share" / "kwalletd"
    if kwallet_dir.is_dir():
        try:
            for f in kwallet_dir.glob("*.kwl"):
                meta = file_meta(f, stats)
                if meta:
                    findings.append(make_finding(
                        "keyrings", "kwallet", f"KDE KWallet file ({f.name})",
                        f, "LOW", meta, None, "KWallet credential store.", args.redact,
                    ))
        except (OSError, PermissionError):
            stats.permission_errors += 1
    return findings


def scan_git_tokens(home: Path, args, stats: Stats):
    findings = []

    git_creds = home / ".git-credentials"
    if git_creds.is_file():
        text = safe_read_text(git_creds, stats)
        meta = file_meta(git_creds, stats)
        if text and meta:
            for line in text.splitlines():
                if line.strip():
                    findings.append(make_finding(
                        "git_tokens", "git_credential_store", "Git credential store entry",
                        git_creds, "HIGH", meta, line.strip(),
                        "Plaintext Git remote URL with embedded username:token.", args.redact,
                    ))

    netrc = home / ".netrc"
    if netrc.is_file():
        text = safe_read_text(netrc, stats)
        meta = file_meta(netrc, stats)
        if text and meta:
            findings.append(make_finding(
                "git_tokens", "netrc", ".netrc credentials", netrc, "HIGH", meta, text,
                "Plaintext machine/login/password entries used by curl, ftp, git, etc.", args.redact,
            ))

    gh_hosts = home / ".config" / "gh" / "hosts.yml"
    if gh_hosts.is_file():
        text = safe_read_text(gh_hosts, stats)
        meta = file_meta(gh_hosts, stats)
        if text and "oauth_token" in text and meta:
            findings.append(make_finding(
                "git_tokens", "github_cli", "GitHub CLI OAuth token", gh_hosts, "HIGH", meta, text,
                "gh CLI stores its OAuth token in plaintext here.", args.redact,
            ))

    npmrc_paths = [home / ".npmrc"]
    for npmrc in npmrc_paths:
        if npmrc.is_file():
            text = safe_read_text(npmrc, stats)
            meta = file_meta(npmrc, stats)
            if text and meta and "_authToken" in text:
                findings.append(make_finding(
                    "git_tokens", "npmrc", "npm auth token (.npmrc)", npmrc, "HIGH", meta, text,
                    "npm registry auth token stored in plaintext.", args.redact,
                ))

    pypirc = home / ".pypirc"
    if pypirc.is_file():
        text = safe_read_text(pypirc, stats)
        meta = file_meta(pypirc, stats)
        if text and meta and "password" in text.lower():
            findings.append(make_finding(
                "git_tokens", "pypirc", "PyPI credentials (.pypirc)", pypirc, "HIGH", meta, text,
                "PyPI upload credentials stored in plaintext.", args.redact,
            ))

    composer_auth = home / ".composer" / "auth.json"
    if composer_auth.is_file():
        text = safe_read_text(composer_auth, stats)
        meta = file_meta(composer_auth, stats)
        if text and meta:
            findings.append(make_finding(
                "git_tokens", "composer_auth", "Composer/PHP auth.json token", composer_auth,
                "HIGH", meta, text, "Contains GitHub/GitLab/Packagist tokens.", args.redact,
            ))

    return findings


def _scan_env_file(fpath: Path, meta: dict, args, stats: Stats):
    findings = []
    text = safe_read_text(fpath, stats)
    if not text:
        return findings
    for lineno, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip().strip("export ").strip()
        val = val.strip().strip("'\"")
        if not val or is_placeholder(val):
            continue
        sensitive = re.search(r"(pass(word)?|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|auth)", key, re.I)
        if not sensitive:
            continue
        findings.append(make_finding(
            "app_credentials", "env_file", f"Secret in {fpath.name} ({key})", fpath,
            "HIGH", meta, val, f".env-style file, line {lineno}.", args.redact,
        ))
    return findings


def _scan_pgpass(fpath: Path, meta: dict, args, stats: Stats):
    findings = []
    text = safe_read_text(fpath, stats)
    if not text:
        return findings
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) >= 5:
            findings.append(make_finding(
                "app_credentials", "pgpass", "PostgreSQL .pgpass credential", fpath, "HIGH",
                meta, line, "hostname:port:database:username:password, always plaintext by design.",
                args.redact,
            ))
    return findings


def _scan_my_cnf(fpath: Path, meta: dict, args, stats: Stats):
    findings = []
    text = safe_read_text(fpath, stats)
    if not text:
        return findings
    m = re.search(r"(?im)^\s*password\s*=\s*(.+)$", text)
    if m and not is_placeholder(m.group(1)):
        findings.append(make_finding(
            "app_credentials", "my_cnf", "MySQL client password (.my.cnf)", fpath, "HIGH",
            meta, m.group(1).strip(), "Plaintext MySQL client credential.", args.redact,
        ))
    return findings


def _scan_filezilla(fpath: Path, meta: dict, args, stats: Stats):
    findings = []
    text = safe_read_text(fpath, stats, max_bytes=2_000_000)
    if not text:
        return findings
    for m in re.finditer(r'<Host>(?P<host>.*?)</Host>.*?<User>(?P<user>.*?)</User>.*?'
                          r'<Pass(?:[^>]*)>(?P<pass>.*?)</Pass>', text, re.S):
        host, user, pw_b64 = m.group("host"), m.group("user"), m.group("pass")
        try:
            pw = base64.b64decode(pw_b64).decode("utf-8", "replace")
        except Exception:
            pw = pw_b64
        findings.append(make_finding(
            "app_credentials", "filezilla", f"FileZilla saved site credential ({host})", fpath,
            "CRITICAL", meta, f"{user}:{pw}", "FileZilla sitemanager.xml stores FTP passwords "
            "base64-encoded (not encrypted).", args.redact,
        ))
    return findings


SPECIAL_APP_HANDLERS = {
    ".env": _scan_env_file,
    ".pgpass": _scan_pgpass,
    ".my.cnf": _scan_my_cnf,
    "sitemanager.xml": _scan_filezilla,
}


def _generic_secret_scan(fpath: Path, meta: dict, args, stats: Stats):
    findings = []
    text = safe_read_text(fpath, stats)
    if not text:
        return findings
    seen = set()
    for m in SECRET_KEY_RE.finditer(text):
        val = m.group("value")
        key = m.group("key")
        if is_placeholder(val) or val in seen:
            continue
        seen.add(val)
        findings.append(make_finding(
            "app_credentials", "config_secret", f"Secret-looking key '{key}' in {fpath.name}",
            fpath, "MEDIUM", meta, val, "Matched generic secret key=value heuristic.", args.redact,
        ))
        if len(seen) >= 25:
            break
    return findings


def scan_app_credentials(home: Path, args, stats: Stats):
    findings = []
    max_depth = args.max_depth
    home_depth = len(home.parts)

    for root, dirs, files in os.walk(home, topdown=True, onerror=lambda e: stats.__setattr__(
            "permission_errors", stats.permission_errors + 1)):
        root_path = Path(root)
        depth = len(root_path.parts) - home_depth
        if depth >= max_depth:
            dirs[:] = []
            continue
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIR_NAMES and not d.startswith(".git")]

        for fname in files:
            if stats.files_scanned >= args.max_files:
                stats.walk_truncated = True
                return findings
            stats.files_scanned += 1

            interesting = fname in INTERESTING_APP_FILES or fname.startswith(INTERESTING_APP_PREFIXES)
            if not interesting:
                continue

            fpath = root_path / fname
            meta = file_meta(fpath, stats)
            if meta is None or meta["size"] > MAX_FILE_BYTES:
                continue

            handler = SPECIAL_APP_HANDLERS.get(fname)
            if handler is None:
                for suffix, h in SPECIAL_APP_HANDLERS.items():
                    if fname == suffix or fname.endswith(suffix):
                        handler = h
                        break
            if handler:
                findings.extend(handler(fpath, meta, args, stats))
            else:
                findings.extend(_generic_secret_scan(fpath, meta, args, stats))

    return findings


SCANNERS = {
    "ssh_keys": scan_ssh_keys,
    "cloud_credentials": scan_cloud_credentials,
    "browser_credentials": scan_browser_credentials,
    "shell_history": scan_shell_history,
    "keyrings": scan_keyrings,
    "git_tokens": scan_git_tokens,
    "app_credentials": scan_app_credentials,
}

# --------------------------------------------------------------------------
# Home directory discovery
# --------------------------------------------------------------------------


def discover_home_dirs(args) -> list:
    if args.path:
        return [Path(p).expanduser() for p in args.path]
    if args.all_users:
        homes = set()
        for base in ("/home", "/Users"):
            base_path = Path(base)
            if base_path.is_dir():
                try:
                    homes.update(p for p in base_path.iterdir() if p.is_dir())
                except PermissionError:
                    pass
        if os.geteuid() == 0 if hasattr(os, "geteuid") else False:
            root_home = Path("/root")
            if root_home.is_dir():
                homes.add(root_home)
        return sorted(homes)
    return [Path.home()]


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------


def c(text, color_key, use_color):
    if not use_color:
        return text
    return f"{COLORS[color_key]}{text}{COLORS['RESET']}"


def print_terminal_report(findings, stats, homes, use_color, brief=False):
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] += 1

    print(c("=" * 70, "DIM", use_color))
    print(c(" credhunter report", "BOLD", use_color))
    print(c("=" * 70, "DIM", use_color))
    print(f" Scanned home(s): {', '.join(str(h) for h in homes)}")
    print(f" Files walked: {stats.files_scanned}   Permission errors: {stats.permission_errors}"
          + ("   (walk truncated - hit max-files cap)" if stats.walk_truncated else ""))
    print(f" Total findings: {len(findings)}")
    for sev in reversed(SEVERITY_ORDER):
        if counts[sev]:
            print(f"   {c(sev.ljust(8), sev, use_color)} {counts[sev]}")
    print(c("=" * 70, "DIM", use_color))

    if brief:
        return

    for f in sorted(findings, key=lambda x: SEVERITY_ORDER.index(x.severity), reverse=True):
        print()
        print(f"{c('[' + f.severity + ']', f.severity, use_color)} {c(f.title, 'BOLD', use_color)}")
        print(f"  category   : {f.category} / {f.subtype}")
        print(f"  path       : {f.path}")
        print(f"  perms/owner: {f.permissions} ({f.owner})"
              f"{'  [WORLD-READABLE]' if f.world_readable else ''}"
              f"{'  [group-readable]' if f.group_readable and not f.world_readable else ''}")
        if f.notes:
            print(f"  notes      : {f.notes}")
        if f.value:
            shown = f.value if len(f.value) < 300 else f.value[:300] + " ...[truncated]"
            print(f"  value      : {c(shown, 'GREEN', use_color)}")
        if f.recommendation:
            print(f"  fix        : {f.recommendation}")


def build_json_report(findings, stats, homes):
    counts = {s: 0 for s in SEVERITY_ORDER}
    by_category = {cat: 0 for cat in CATEGORIES}
    for f in findings:
        counts[f.severity] += 1
        by_category[f.category] += 1
    return {
        "scan_time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "scanned_homes": [str(h) for h in homes],
        "files_scanned": stats.files_scanned,
        "permission_errors": stats.permission_errors,
        "walk_truncated": stats.walk_truncated,
        "total_findings": len(findings),
        "counts_by_severity": counts,
        "counts_by_category": by_category,
        "findings": [asdict(f) for f in findings],
    }


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="credhunter",
        description="Scan Linux home directories for exposed credentials.",
    )
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument("--path", action="append", metavar="DIR",
                        help="Home directory to scan (repeatable). Default: current user's home.")
    scope.add_argument("--all-users", action="store_true",
                        help="Scan every home directory under /home (and /root if run as root).")

    parser.add_argument("--category", action="append", choices=CATEGORIES,
                         help="Only run the given category (repeatable). Default: all.")
    parser.add_argument("--min-severity", choices=SEVERITY_ORDER, default="INFO",
                         help="Only report findings at or above this severity.")
    parser.add_argument("--redact", action="store_true",
                         help="Mask secret values in output instead of showing them in full.")
    parser.add_argument("--json", action="store_true", help="Emit structured JSON instead of text.")
    parser.add_argument("-o", "--output", metavar="FILE", help="Write the report to FILE instead of stdout.")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors in terminal output.")
    parser.add_argument("--brief", action="store_true", help="Terminal mode: print only the summary counts.")
    parser.add_argument("--max-depth", type=int, default=MAX_WALK_DEPTH,
                         help=f"Max recursion depth for the app_credentials walk (default {MAX_WALK_DEPTH}).")
    parser.add_argument("--max-files", type=int, default=MAX_WALK_FILES,
                         help=f"Max files visited during the app_credentials walk (default {MAX_WALK_FILES}).")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    homes = discover_home_dirs(args)
    categories = args.category or CATEGORIES

    stats = Stats()
    all_findings = []
    for home in homes:
        if not home.is_dir():
            continue
        for cat in categories:
            try:
                all_findings.extend(SCANNERS[cat](home, args, stats))
            except PermissionError:
                stats.permission_errors += 1

    min_rank = SEVERITY_ORDER.index(args.min_severity)
    all_findings = [f for f in all_findings if SEVERITY_ORDER.index(f.severity) >= min_rank]

    if args.json:
        report = build_json_report(all_findings, stats, homes)
        text_out = json.dumps(report, indent=2)
    else:
        use_color = not args.no_color and sys.stdout.isatty()
        if args.output:
            use_color = False
        import io
        buf = io.StringIO()
        real_stdout = sys.stdout
        sys.stdout = buf
        try:
            print_terminal_report(all_findings, stats, homes, use_color, brief=args.brief)
        finally:
            sys.stdout = real_stdout
        text_out = buf.getvalue()

    if args.output:
        Path(args.output).write_text(text_out, encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(text_out)

    return 0


if __name__ == "__main__":
    sys.exit(main())
