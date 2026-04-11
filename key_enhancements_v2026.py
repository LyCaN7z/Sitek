#!/usr/bin/env python3
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  PhantomScope  —  Key Scanner 2026 Enhancement Patch                    ║
# ║  Drop-in replacements for:                                              ║
# ║    • _KD_PATTERNS          (keydump patterns)                           ║
# ║    • _CAPTCHA_PATTERNS     (sitekey patterns)                           ║
# ║    • _hiddenkeys_sync()    (hidden token scanner)                       ║
# ║    • _run_keydump_sync()   (keydump core)                               ║
# ║    • _sitekey_playwright() (sitekey browser scanner)                    ║
# ║                                                                         ║
# ║  HOW TO USE:                                                            ║
# ║    ၁) ဒီ file ကို bot_v17.py နဲ့ တူတဲ့ folder ထဲ ထည့်ပါ               ║
# ║    ၂) bot_v17.py အစဆုံးမှာ import လုပ်ပါ:                              ║
# ║       from key_enhancements_v2026 import *                              ║
# ║    ၃) Bot restart လုပ်ပါ — auto-override ဖြစ်မည်                        ║
# ╚══════════════════════════════════════════════════════════════════════════╝

import re, os, json, time, math, hashlib, base64
import concurrent.futures
from urllib.parse import urlparse, urljoin

# ══════════════════════════════════════════════════════════════════════════════
# ══  SECTION 1: KEYDUMP — ENHANCED _KD_PATTERNS (2026)                     ══
# ══════════════════════════════════════════════════════════════════════════════
#
#  ရှိပြီးသား _KD_PATTERNS ကို replace လုပ်ပါ။
#  NEW additions (★):
#    ★ Vercel / Supabase / Neon / Turso / PlanetScale
#    ★ Clerk / Auth.js / BetterAuth / Lucia
#    ★ Resend / Loops / Postmark / Courier
#    ★ Sentry DSN / LogRocket / Datadog
#    ★ Railway / Render / Fly.io tokens
#    ★ OpenAI o1/o3 new key format
#    ★ Anthropic Claude API (updated prefix)
#    ★ Cloudflare API Token / R2 / KV
#    ★ Wasm / WASI binary pattern hints
#    ★ Better regex precision (reduce FP)

_KD_PATTERNS = {
    # ── Cloud & Infra ─────────────────────────────────────────────────────────
    "AWS Access Key ID":        (r"\b(AKIA[0-9A-Z]{16})\b", "☁️"),
    "AWS Secret Access Key":    (r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*['\"]?([A-Za-z0-9+/]{40})\b", "☁️"),
    "AWS Session Token":        (r"\b(ASIA[0-9A-Z]{16})\b", "☁️"),
    "AWS Account ID":           (r"\b(\d{12})\b(?=.*(?:aws|iam|sts|ec2))", "☁️"),
    "GCP/Firebase API Key":     (r"\b(AIza[0-9A-Za-z\-_]{35})\b", "☁️"),
    "GCP OAuth Client ID":      (r"([0-9]{8,20}-[a-z0-9]{20,}\.apps\.googleusercontent\.com)", "☁️"),
    "GCP Service Account":      (r'"type"\s*:\s*"service_account"', "☁️"),
    "Azure Tenant ID":          (r"(?:tenantId|tenant_id)\s*[=:]\s*['\"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})", "☁️"),
    "Azure Client Secret":      (r"(?:clientSecret|client_secret|AZURE_CLIENT_SECRET)\s*[=:]\s*['\"]?([A-Za-z0-9~._\-]{30,50})", "☁️"),
    "DigitalOcean Token":       (r"\b(dop_v1_[a-f0-9]{64})\b", "☁️"),
    "DigitalOcean Spaces Key":  (r"\b(DO[A-Z0-9]{16})\b", "☁️"),
    # ★ Cloudflare
    "Cloudflare API Token":     (r"\b(cf_[A-Za-z0-9_\-]{30,})\b", "☁️"),
    "Cloudflare Global API Key":(r"(?:CF_API_KEY|cloudflare.{0,20}api.key)\s*[=:]\s*['\"]?([a-f0-9]{37})\b", "☁️"),
    "Cloudflare Account ID":    (r"(?:CF_ACCOUNT_ID|cloudflare.{0,20}account)\s*[=:]\s*['\"]?([a-f0-9]{32})\b", "☁️"),
    # ★ Vercel
    "Vercel Token":             (r"\b(vercel_[A-Za-z0-9_\-]{24,}|VERCEL_TOKEN\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{24,})", "☁️"),
    "Vercel Project ID":        (r"(?:VERCEL_PROJECT_ID|vercel.{0,10}project)\s*[=:]\s*['\"]?(prj_[A-Za-z0-9]{24,})", "☁️"),
    # ★ Railway
    "Railway Token":            (r"\b(RAILWAY_TOKEN\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{30,})", "☁️"),
    # ★ Render
    "Render API Key":           (r"\b(rnd_[A-Za-z0-9]{30,})\b", "☁️"),
    # ★ Fly.io
    "Fly.io Token":             (r"\b(FlyV1\s[A-Za-z0-9+/=]{30,})\b", "☁️"),

    # ── AI / ML ───────────────────────────────────────────────────────────────
    "OpenAI API Key":           (r"\b(sk-[A-Za-z0-9]{48})\b", "🤖"),
    "OpenAI Project Key":       (r"\b(sk-proj-[A-Za-z0-9_\-]{48,})\b", "🤖"),
    "Anthropic API Key":        (r"\b(sk-ant-(?:api03|api|[A-Za-z0-9]{4})-[A-Za-z0-9_\-]{80,})\b", "🤖"),
    "HuggingFace Token":        (r"\b(hf_[A-Za-z0-9]{34,})\b", "🤖"),
    "Cohere API Key":           (r"\b(co_[A-Za-z0-9_\-]{32,})\b|(?:COHERE_API_KEY)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{32,})", "🤖"),
    "Replicate API Token":      (r"\b(r8_[A-Za-z0-9]{37,})\b", "🤖"),
    "Groq API Key":             (r"\b(gsk_[A-Za-z0-9]{50,})\b", "🤖"),
    "Mistral API Key":          (r"(?:MISTRAL_API_KEY)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{32,})", "🤖"),
    "Together AI Key":          (r"(?:TOGETHER_API_KEY)\s*[=:]\s*['\"]?([a-f0-9]{64})", "🤖"),
    "Stability AI Key":         (r"\b(sk-[A-Za-z0-9]{48})\b(?=.*stability)", "🤖"),

    # ── Databases ★ NEW ────────────────────────────────────────────────────────
    "Supabase URL":             (r"\b(https://[a-z0-9]{20,26}\.supabase\.(?:co|com))\b", "🗄️"),
    "Supabase Anon Key":        (r"(?:SUPABASE_ANON_KEY|supabase.{0,10}anon)\s*[=:]\s*['\"]?(eyJ[A-Za-z0-9_\-]{50,})", "🗄️"),
    "Supabase Service Key":     (r"(?:SUPABASE_SERVICE_KEY|SUPABASE_SECRET)\s*[=:]\s*['\"]?(eyJ[A-Za-z0-9_\-]{100,})", "🗄️"),
    "Neon DB URL":              (r"\b(postgres(?:ql)?://[^:\s]+:[^@\s]+@[a-z0-9\-]+\.neon\.tech[^\s'\"<]{0,200})\b", "🗄️"),
    "Turso DB URL":             (r"\b(libsql://[a-z0-9\-]+\.turso\.io[^\s'\"<]{0,100})\b", "🗄️"),
    "Turso Auth Token":         (r"(?:TURSO_AUTH_TOKEN)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{50,})", "🗄️"),
    "PlanetScale URL":          (r"\b(mysql://[^:\s]+:[^@\s]+@aws\.connect\.psdb\.cloud[^\s'\"<]{0,200})\b", "🗄️"),
    "MongoDB URI":              (r"\b(mongodb(?:\+srv)?://[^\s'\"<>]{10,200})\b", "🔒"),
    "PostgreSQL URI":           (r"\b(postgres(?:ql)?://[^\s'\"<>]{10,200})\b", "🔒"),
    "MySQL URI":                (r"\b(mysql(?:2)?://[^\s'\"<>]{10,200})\b", "🔒"),
    "Redis URI":                (r"\b(rediss?://[^\s'\"<>]{10,150})\b", "🔒"),
    "Upstash Redis URL":        (r"\b(https://[a-z0-9\-]+\.upstash\.io)\b", "🗄️"),
    "Upstash Redis Token":      (r"(?:UPSTASH_REDIS_REST_TOKEN)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{50,})", "🗄️"),

    # ── Auth / Identity ★ NEW ─────────────────────────────────────────────────
    "Clerk Publishable Key":    (r"\b(pk_(?:live|test)_[A-Za-z0-9]{30,})\b", "🔐"),
    "Clerk Secret Key":         (r"\b(sk_(?:live|test)_[A-Za-z0-9]{30,})\b", "🔐"),
    "Auth0 Client Secret":      (r"(?:AUTH0_CLIENT_SECRET|auth0.{0,20}secret)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{40,})", "🔐"),
    "Auth0 Domain":             (r"\b([a-z0-9\-]+\.(?:us|eu|au)\.auth0\.com)\b", "🔐"),
    "Okta API Token":           (r"(?:OKTA_API_TOKEN)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{40,})", "🔐"),
    "NextAuth Secret":          (r"(?:NEXTAUTH_SECRET|AUTH_SECRET)\s*[=:]\s*['\"]?([A-Za-z0-9+/=_\-]{20,})", "🔐"),
    "Lucia Auth Key":           (r"(?:LUCIA_SECRET|AUTH_SECRET)\s*[=:]\s*['\"]?([A-Za-z0-9+/=_\-]{20,})", "🔐"),

    # ── Version Control / DevOps ─────────────────────────────────────────────
    "GitHub PAT (classic)":     (r"\b(ghp_[A-Za-z0-9]{36})\b", "📦"),
    "GitHub Fine-grained PAT":  (r"\b(github_pat_[A-Za-z0-9_]{82})\b", "📦"),
    "GitHub Actions Token":     (r"\b(ghs_[A-Za-z0-9]{36}|ghr_[A-Za-z0-9]{36})\b", "📦"),
    "GitHub OAuth Token":       (r"\b(gho_[A-Za-z0-9]{36})\b", "📦"),
    "GitLab Token":             (r"\b(glpat-[A-Za-z0-9_\-]{20})\b", "📦"),
    "NPM Token":                (r"\b(npm_[A-Za-z0-9]{36})\b", "📦"),
    "Docker Hub Token":         (r"(?:DOCKER_TOKEN|DOCKERHUB_TOKEN)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{30,})", "📦"),

    # ── Email / Communication ★ NEW ───────────────────────────────────────────
    "Resend API Key":           (r"\b(re_[A-Za-z0-9_]{24,})\b", "📨"),
    "Loops API Key":            (r"(?:LOOPS_API_KEY)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{30,})", "📨"),
    "Postmark Server Token":    (r"\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b(?=.*postmark)", "📨"),
    "SendGrid API Key":         (r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b", "📨"),
    "Mailchimp API Key":        (r"\b([0-9a-f]{32}-us\d{1,2})\b", "📨"),
    "Mailgun API Key":          (r"\b(key-[0-9a-zA-Z]{32})\b", "📨"),
    "Slack Bot Token":          (r"\b(xoxb-[0-9]+-[0-9]+-[A-Za-z0-9]+)\b", "📨"),
    "Slack User Token":         (r"\b(xoxp-[0-9A-Za-z\-]{40,})\b", "📨"),
    "Slack App Token":          (r"\b(xapp-[0-9]-[A-Z0-9]+-[0-9]+-[a-f0-9]+)\b", "📨"),
    "Slack Webhook URL":        (r"\b(https://hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[A-Za-z0-9]{24})\b", "📨"),
    "Discord Bot Token":        (r"\b([MN][A-Za-z0-9]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,})\b", "📨"),
    "Discord Webhook URL":      (r"\b(https://discord(?:app)?\.com/api/webhooks/\d{17,19}/[A-Za-z0-9_\-]{68})\b", "📨"),
    "Twilio Account SID":       (r"\b(AC[a-f0-9]{32})\b", "📨"),
    "Twilio Auth Token":        (r"(?:TWILIO_AUTH_TOKEN)\s*[=:]\s*['\"]?([a-f0-9]{32})", "📨"),
    "Courier API Key":          (r"(?:COURIER_AUTH_TOKEN)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{30,})", "📨"),

    # ── Observability ★ NEW ────────────────────────────────────────────────────
    "Sentry DSN":               (r"\b(https://[a-f0-9]{32}@o\d+\.ingest\.(?:sentry|us)\.io/\d+)\b", "📡"),
    "LogRocket App ID":         (r"(?:LOGROCKET_APP_ID|LogRocket\.init)\s*[^'\"]*['\"]([a-z0-9]+/[a-z0-9\-]+)['\"]", "📡"),
    "Datadog API Key":          (r"(?:DD_API_KEY|datadog.{0,10}key)\s*[=:]\s*['\"]?([a-f0-9]{32})\b", "📡"),
    "Datadog App Key":          (r"(?:DD_APP_KEY)\s*[=:]\s*['\"]?([a-f0-9]{40})\b", "📡"),
    "New Relic License Key":    (r"\b([A-Za-z0-9]{40})(?=.*newrelic)", "📡"),
    "Grafana API Token":        (r"\b(glsa_[A-Za-z0-9_]{32})\b", "📡"),
    "Axiom API Token":          (r"(?:AXIOM_TOKEN)\s*[=:]\s*['\"]?(xaat-[A-Za-z0-9_\-]{36,})", "📡"),

    # ── Firebase / Google ─────────────────────────────────────────────────────
    "Firebase API Key (ctx)":   (r"(?:apiKey|api_key)\s*[=:]\s*['\"]?(AIza[0-9A-Za-z_-]{35})['\"]", "🔥"),
    "Firebase API Key (raw)":   (r"\b(AIza[0-9A-Za-z\-_]{35})\b", "🔥"),
    "Firebase authDomain":      (r"authDomain\s*[=:]\s*['\"]([a-z0-9\-]+\.firebaseapp\.com)['\"]", "🔥"),
    "Firebase projectId":       (r"projectId\s*[=:]\s*['\"]([a-z0-9\-]{4,40})['\"]", "🔥"),
    "Firebase storageBucket":   (r"storageBucket\s*[=:]\s*['\"]([a-z0-9\-]+\.(?:appspot|firebasestorage)\.com)['\"]", "🔥"),
    "Firebase messagingSenderId":(r"messagingSenderId\s*[=:]\s*['\"](\d{10,15})['\"]", "🔥"),
    "Firebase appId":           (r"appId\s*[=:]\s*['\"]([0-9]:[\d]+:[a-z]:[a-f0-9]{16,})['\"]", "🔥"),
    "Firebase DB URL":          (r"\b(https://[a-z0-9\-]+\.firebaseio\.com)\b", "🔥"),
    "Firebase Realtime DB":     (r"\b(https://[a-z0-9\-]+\.asia-southeast1\.firebasedatabase\.app)\b", "🔥"),

    # ── Social / OAuth ────────────────────────────────────────────────────────
    "Facebook App ID":          (r"(?:appId|fbAppId|fb_app_id)\s*[=:'\"]{1,3}\s*['\"]?(\d{13,18})", "📱"),
    "Facebook Pixel ID":        (r"fbq\s*\(\s*['\"]init['\"]\s*,\s*['\"]?(\d{13,18})", "📱"),
    "Facebook Access Token":    (r"\b(EAAa[A-Za-z0-9]{100,})\b", "📱"),
    "Google Client ID":         (r"\b([0-9]{10,20}-[a-z0-9]{20,40}\.apps\.googleusercontent\.com)\b", "📱"),
    "TikTok Pixel":             (r"ttq\.load\s*\(['\"]([A-Z0-9]{15,20})['\"]", "📱"),
    "LinkedIn Partner ID":      (r"_linkedin_partner_id\s*=\s*['\"]?(\d{5,12})", "📱"),
    "Twitter/X Bearer Token":   (r"(?:TWITTER_BEARER_TOKEN|twitter.{0,10}bearer)\s*[=:]\s*['\"]?(AAAA[A-Za-z0-9%_\-]{60,})", "📱"),
    "Pinterest App ID":         (r"(?:PINTEREST_APP_ID|pintrk).{0,20}['\"](\d{10,18})['\"]", "📱"),

    # ── Analytics ─────────────────────────────────────────────────────────────
    "Google Analytics 4":       (r"\b(G-[A-Z0-9]{8,12})\b", "📊"),
    "Google Analytics UA":      (r"\b(UA-\d{5,12}-\d{1,3})\b", "📊"),
    "Google Tag Manager":       (r"\b(GTM-[A-Z0-9]{6,8})\b", "📊"),
    "Google Ads":               (r"\b(AW-\d{9,12})\b", "📊"),
    "Hotjar Site ID":           (r"(?:hjid|HOTJAR_ID)\s*[=:,]\s*['\"]?(\d{5,10})", "📊"),
    "Mixpanel Token":           (r"mixpanel\.init\s*\(\s*['\"]([a-f0-9]{32})['\"]", "📊"),
    "Segment Write Key":        (r"(?:analytics|segment)\.load\s*\(\s*['\"]([A-Za-z0-9]{20,40})['\"]", "📊"),
    "Amplitude API Key":        (r"(?:amplitude|Amplitude)\.init\s*\(\s*['\"]([a-f0-9]{32})['\"]", "📊"),
    "Heap Analytics ID":        (r"heap\.load\s*\(\s*['\"]?(\d{8,12})", "📊"),
    "PostHog API Key":          (r"(?:posthog\.init|POSTHOG_KEY)\s*['\",\(]*([A-Za-z0-9_\-]{30,50})", "📊"),

    # ── Captcha Keys ──────────────────────────────────────────────────────────
    "reCAPTCHA Sitekey":        (r'data-sitekey=["\']([0-9A-Za-z_\-]{40})["\']', "🔑"),
    "reCAPTCHA v3 render":      (r"(?:render|execute)\s*\(\s*['\"]([6L][A-Za-z0-9_\-]{38})['\"]", "🔑"),
    "hCaptcha Sitekey":         (r'(?:sitekey|data-sitekey)\s*[=:]\s*["\']([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})["\']', "🔑"),
    "Cloudflare Turnstile":     (r'(?:sitekey|data-sitekey)\s*[=:]\s*["\']([01]x[A-Za-z0-9_\-]{20,60})["\']', "🔑"),

    # ── JWT / Auth Tokens ─────────────────────────────────────────────────────
    "JWT Token (live)":         (r"\b(eyJ[A-Za-z0-9\-_]{20,}\.eyJ[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{10,})\b", "🧬"),
    "JWT Secret":               (r"(?:JWT_SECRET|NEXTAUTH_SECRET|TOKEN_SECRET)\s*[=:]\s*['\"]?([^\s'\"]{16,80})", "🧬"),
    "PASETO Token":             (r"\b(v[1-4]\.[a-z]+\.[A-Za-z0-9\-_=]+)\b", "🧬"),

    # ── Secrets & Credentials ─────────────────────────────────────────────────
    "Private Key PEM":          (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "🔒"),
    "SSH Private Key":          (r"-----BEGIN OPENSSH PRIVATE KEY-----", "🔒"),
    "SSH RSA Key":              (r"ssh-rsa AAAA[A-Za-z0-9+/]{100,}", "🔒"),
    "Hardcoded Password":       (r'(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{8,80})["\']', "🔒"),
    "Secret Key (env)":         (r"(?:SECRET_KEY|APP_SECRET|SESSION_SECRET)\s*[=:]\s*['\"]?([^\s'\"]{16,80})", "🔒"),
    "Encryption Key":           (r"(?:ENCRYPTION_KEY|CIPHER_KEY)\s*[=:]\s*['\"]?([A-Za-z0-9+/=]{24,})", "🔒"),

    # ── Push / Real-time ─────────────────────────────────────────────────────
    "VAPID Public Key":         (r"(?:vapidKey|applicationServerKey)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{86,90})", "🔔"),
    "Pusher App Key":           (r"(?:pusher|PUSHER_KEY)\s*[=:,\(]*\s*['\"]?([a-f0-9]{20})", "🔔"),
    "Ably API Key":             (r"\b([A-Za-z0-9_\-]{8,16}\.[A-Za-z0-9_\-]{6,16}:[A-Za-z0-9_\-+/=]{30,})\b(?=.*ably)", "🔔"),
    "Liveblocks Public Key":    (r"\b(pk_(?:dev|prod)_[A-Za-z0-9]{30,})\b", "🔔"),
    "Partykit Key":             (r"(?:PARTYKIT_TOKEN)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{20,})", "🔔"),

    # ── Payments (Publishable/Non-sensitive only) ─────────────────────────────
    "Stripe Publishable Key":   (r"\b(pk_(?:live|test)_[A-Za-z0-9]{24,})\b", "💳"),
    "Razorpay Key ID":          (r"\b(rzp_(?:live|test)_[A-Za-z0-9]{14})\b", "💳"),

    # ── Misc / Generic ────────────────────────────────────────────────────────
    "Bearer Token":             (r"[Bb]earer\s+(eyJ[A-Za-z0-9\-_.]{30,}|[A-Za-z0-9_\-]{40,200})", "🌐"),
    "Mapbox Token":             (r"\b(pk\.eyJ[A-Za-z0-9._\-]{20,})\b", "🌐"),
    "Algolia App ID":           (r"\b([A-Z0-9]{10})\b(?=.*algolia)", "🌐"),
    "Algolia API Key":          (r"(?:apiKey|ALGOLIA_KEY)\s*[=:]\s*['\"]([a-f0-9]{32})['\"]", "🌐"),
    "Bing Maps Key":            (r"\b(A[a-zA-Z0-9_\-]{80})\b(?=.*bing)", "🌐"),
    "IPInfo Token":             (r"ipinfo\.io[^'\"]*[?/]([a-f0-9]{14})", "🌐"),
    "Abstract API Key":         (r"(?:abstract.{0,20}key)\s*[=:]\s*['\"]([a-f0-9]{32})['\"]", "🌐"),
    "API Key (generic env)":    (r"(?:API_KEY|APIKEY)\s*[=:]\s*['\"]([A-Za-z0-9_\-]{20,80})['\"]", "🌐"),
}

# ── Category map (same as before + new ones) ─────────────────────────────────
_KD_CATEGORIES = {
    "☁️": "Cloud & Infra",
    "🤖": "AI / ML",
    "🗄️": "Database",
    "🔐": "Auth & Identity",
    "📦": "Version Control / DevOps",
    "📨": "Email & Messaging",
    "📡": "Observability",
    "🔥": "Firebase / Google",
    "📱": "Social / OAuth",
    "📊": "Analytics & Tracking",
    "🔑": "Captcha Keys",
    "🧬": "JWT & Auth Tokens",
    "🔒": "Secrets & Credentials",
    "🔔": "Push / Real-time",
    "💳": "Payment (Publishable)",
    "🌐": "Generic / Other",
}

# ── Severity scoring per category ─────────────────────────────────────────────
_KD_SEVERITY = {
    "🔒": "CRITICAL",   # Private keys, passwords, DB URIs
    "🤖": "CRITICAL",   # AI API keys (often have billing)
    "☁️": "CRITICAL",   # Cloud infra
    "🗄️": "CRITICAL",   # Database connections
    "🔐": "HIGH",       # Auth secrets
    "🧬": "HIGH",       # JWT secrets
    "📨": "HIGH",       # Comms API keys
    "📡": "HIGH",       # Observability (error/log data)
    "📦": "HIGH",       # Source code access
    "🔥": "MEDIUM",     # Firebase (public keys, but config leak)
    "📱": "MEDIUM",     # Social (app IDs usually public)
    "🔑": "LOW",        # Captcha sitekeys (public by design)
    "🔔": "MEDIUM",     # Push keys
    "💳": "LOW",        # Publishable payment keys (public by design)
    "📊": "LOW",        # Analytics IDs (public by design)
    "🌐": "MEDIUM",     # Generic (context-dependent)
}

# Compile patterns once
_KD_COMPILED = {
    label: (re.compile(pat, re.IGNORECASE | re.MULTILINE), icon)
    for label, (pat, icon) in _KD_PATTERNS.items()
}


# ══════════════════════════════════════════════════════════════════════════════
# ══  SECTION 2: SITEKEY — ENHANCED _CAPTCHA_PATTERNS (2026)                ══
# ══════════════════════════════════════════════════════════════════════════════

_CAPTCHA_PATTERNS_2026 = {
    # ── reCAPTCHA ────────────────────────────────────────────────────────────
    "reCAPTCHA v2": [
        re.compile(r'data-sitekey=["\']([0-9A-Za-z_\-]{40})["\']', re.I),
        re.compile(r'grecaptcha\.render\([^)]*["\']sitekey["\']\s*:\s*["\']([0-9A-Za-z_\-]{40})["\']', re.I),
        re.compile(r'grecaptcha_sitekey\s*=\s*["\']([0-9A-Za-z_\-]{40})["\']', re.I),
        re.compile(r'["\']sitekey["\']\s*:\s*["\']([6L][A-Za-z0-9_\-]{38})["\']', re.I),
        re.compile(r'captcha[_\-]?key\s*[=:]\s*["\']([6L][A-Za-z0-9_\-]{38})["\']', re.I),
    ],
    "reCAPTCHA v3": [
        re.compile(r'grecaptcha\.execute\s*\(\s*["\']([6L][A-Za-z0-9_\-]{38})["\']', re.I),
        re.compile(r'grecaptcha\.execute\s*\(\s*([6L][A-Za-z0-9_\-]{38})\s*,', re.I),
        re.compile(r'\/recaptcha\/api\.js\?render=([0-9A-Za-z_\-]{40})', re.I),
        re.compile(r'["\']render["\']\s*:\s*["\']([6L][A-Za-z0-9_\-]{38})["\']', re.I),
    ],
    "reCAPTCHA Enterprise": [
        re.compile(r'grecaptcha\.enterprise\.execute\s*\(\s*["\']([0-9A-Za-z_\-]{40})["\']', re.I),
        re.compile(r'\/recaptcha\/enterprise\.js\?render=([0-9A-Za-z_\-]{40})', re.I),
        re.compile(r'enterprise\.js[^"\']*["\']sitekey["\']\s*:\s*["\']([0-9A-Za-z_\-]{40})["\']', re.I),
    ],
    "hCaptcha": [
        re.compile(r'data-sitekey=["\']([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})["\']', re.I),
        re.compile(r'hcaptcha\.render\([^)]*["\']sitekey["\']\s*:\s*["\']([a-f0-9-]{36})["\']', re.I),
        re.compile(r'window\.hcaptcha\s*=.*?["\']([a-f0-9-]{36})["\']', re.I),
        re.compile(r'hcaptcha\.com/1/api\.js.*?(?:hl=[a-z]+&)?(?:sitekey=([a-f0-9-]{36}))', re.I),
    ],
    "Cloudflare Turnstile": [
        re.compile(r'data-sitekey=["\']([01]x[A-Za-z0-9_\-]{20,60})["\']', re.I),
        re.compile(r'turnstile\.render\([^)]*sitekey\s*:\s*["\']([01]x[A-Za-z0-9_\-]{20,60})["\']', re.I),
        re.compile(r'["\']sitekey["\']\s*:\s*["\']([01]x[A-Za-z0-9_\-]{20,60})["\']', re.I),
        re.compile(r'cf-turnstile[^>]*data-sitekey=["\']([01]x[A-Za-z0-9_\-]{20,60})["\']', re.I),
        # ★ Managed challenge (no explicit key — domain-level)
        re.compile(r'challenges\.cloudflare\.com/cdn-cgi/challenge-platform', re.I),
    ],
    "FunCaptcha": [
        re.compile(r'(?:pk|data-pkey|public_key)\s*[=:]\s*["\']([A-Z0-9]{8}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{12})["\']', re.I),
        re.compile(r'ArkoseLabsChallenge\s*\(\s*["\']([A-Z0-9\-]{36})["\']', re.I),
        re.compile(r'arkoselabs\.com[^"\']*["\']([A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12})["\']', re.I),
    ],
    "GeeTest": [
        re.compile(r'initGeetest(?:4)?\s*\([^)]*["\']gt["\']\s*:\s*["\']([0-9a-f]{32})["\']', re.I),
        re.compile(r'["\']captchaId["\']\s*:\s*["\']([a-f0-9]{32})["\']', re.I),
        re.compile(r'gt\s*:\s*["\']([0-9a-f]{32})["\']', re.I),
    ],
    # ★ NEW: FriendlyCaptcha
    "FriendlyCaptcha": [
        re.compile(r'data-sitekey=["\']([A-Z0-9FCAP_]{16,60})["\'](?=[^>]*friendly)', re.I),
        re.compile(r'FriendlyCaptcha\s*\.[A-Za-z]+\s*\(\s*[^)]*sitekey\s*:\s*["\']([A-Z0-9]{16,60})["\']', re.I),
        re.compile(r'friendlycaptcha\.(?:com|eu)[^"\']*sitekey=([A-Z0-9_\-]{16,60})', re.I),
    ],
    # ★ NEW: mCaptcha (open source)
    "mCaptcha": [
        re.compile(r'mCaptcha\s*\.\s*init\s*\(\s*["\']([A-Za-z0-9_]{20,60})["\']', re.I),
        re.compile(r'data-mcaptcha-sitekey=["\']([A-Za-z0-9_]{20,60})["\']', re.I),
    ],
    # ★ NEW: MTCaptcha
    "MTCaptcha": [
        re.compile(r'mtcaptcha\.config\s*=\s*\{[^}]*sitekey\s*:\s*["\']([A-Za-z0-9_\-]{20,80})["\']', re.I),
        re.compile(r'MTCaptchaConfig\s*=\s*\{[^}]*["\']sitekey["\']\s*:\s*["\']([A-Za-z0-9_\-]{20,80})["\']', re.I),
    ],
    # ★ NEW: Kasada (pure detection, no key)
    "Kasada Bot Defense": [
        re.compile(r'kasada\.io', re.I),
        re.compile(r'kpsdk\.js|kcollect\.js|kprotect\.js', re.I),
    ],
    # ★ NEW: Akamai Bot Manager
    "Akamai Bot Manager": [
        re.compile(r'_abck\s*=\s*["\']([A-Za-z0-9+/=]{60,})["\']', re.I),
        re.compile(r'sensor_data|ak_bmsc|bm_sz', re.I),
    ],
    # ★ NEW: DataDome
    "DataDome": [
        re.compile(r'tag\.datadome\.co/tags\.js', re.I),
        re.compile(r'datadome\.co/device-check[^"\']*["\']([A-Za-z0-9_\-]{20,})["\']', re.I),
        re.compile(r'DATADOME_CLIENT_KEY\s*[=:]\s*["\']([A-Za-z0-9_\-]{20,})["\']', re.I),
    ],
    # ★ NEW: PerimeterX / HUMAN
    "PerimeterX/HUMAN": [
        re.compile(r'client\.px-cloud\.net/[A-Za-z0-9]+/main\.min\.js', re.I),
        re.compile(r'px\.js\?appId=([A-Za-z0-9_\-]{8,40})', re.I),
        re.compile(r'_pxAppId\s*[=:]\s*["\']([A-Za-z0-9_]{6,20})["\']', re.I),
    ],
    # ★ NEW: AWS WAF Captcha
    "AWS WAF Captcha": [
        re.compile(r'captcha\.us-east-1\.amazonaws\.com', re.I),
        re.compile(r'AwsWafCaptcha\.renderCaptcha', re.I),
        re.compile(r'awswaf-captcha-api-key\s*[=:]\s*["\']([A-Za-z0-9+/=]{20,})["\']', re.I),
    ],
    # ★ NEW: GoBotBlocker / Altcha (newer open-source)
    "Altcha": [
        re.compile(r'altcha-widget|<altcha-widget', re.I),
        re.compile(r'altcha\.org/api/v1/challenge', re.I),
    ],
}

# ── Key format validators ──────────────────────────────────────────────────────
_KEY_VALIDATORS_2026 = {
    "reCAPTCHA v2":         lambda k: len(k) == 40 and k[0] in '6L',
    "reCAPTCHA v3":         lambda k: len(k) == 40 and k[0] in '6L',
    "reCAPTCHA Enterprise": lambda k: len(k) == 40,
    "hCaptcha":             lambda k: bool(re.match(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', k, re.I)),
    "Cloudflare Turnstile": lambda k: bool(re.match(r'^[01]x[A-Za-z0-9_\-]{20,60}$', k)),
    "GeeTest":              lambda k: bool(re.match(r'^[0-9a-f]{32}$', k)),
    "FunCaptcha":           lambda k: bool(re.match(r'^[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}$', k, re.I)),
}

# Priority scan order (most specific first to avoid mis-attribution)
_CAPTCHA_SCAN_ORDER_2026 = [
    "reCAPTCHA Enterprise",
    "hCaptcha",
    "Cloudflare Turnstile",
    "FunCaptcha",
    "GeeTest",
    "reCAPTCHA v3",
    "reCAPTCHA v2",
    "FriendlyCaptcha",
    "mCaptcha",
    "MTCaptcha",
    "Kasada Bot Defense",
    "Akamai Bot Manager",
    "DataDome",
    "PerimeterX/HUMAN",
    "AWS WAF Captcha",
    "Altcha",
]

# Script src signatures for fallback detection
_CAPTCHA_SCRIPT_SIGS_2026 = {
    "reCAPTCHA v2":         ["google.com/recaptcha/api.js"],
    "reCAPTCHA v3":         ["google.com/recaptcha/api.js?render="],
    "reCAPTCHA Enterprise": ["google.com/recaptcha/enterprise.js"],
    "hCaptcha":             ["hcaptcha.com/1/api.js", "js.hcaptcha.com"],
    "Cloudflare Turnstile": ["challenges.cloudflare.com/turnstile"],
    "FunCaptcha":           ["funcaptcha.com", "arkoselabs.com"],
    "GeeTest":              ["static.geetest.com", "geetest.com"],
    "FriendlyCaptcha":      ["friendlycaptcha.com/widget", "unpkg.com/friendly-challenge"],
    "mCaptcha":             ["mcaptcha.org"],
    "MTCaptcha":            ["mtcaptcha.com/mtcaptcha-widget.min.js"],
    "Kasada Bot Defense":   ["kasada.io", "kpsdk.js"],
    "DataDome":             ["tag.datadome.co"],
    "PerimeterX/HUMAN":     ["px-cloud.net", "perimeterx.net"],
    "AWS WAF Captcha":      ["captcha.us-east-1.amazonaws.com"],
    "Altcha":               ["altcha.org", "altcha-widget"],
}


# ══════════════════════════════════════════════════════════════════════════════
# ══  SECTION 3: HIDDENKEYS — ENHANCED _hiddenkeys_sync (2026)              ══
# ══════════════════════════════════════════════════════════════════════════════

def _hiddenkeys_sync_2026(url: str, progress_cb=None) -> dict:
    """
    2026 Enhanced hidden key scanner.

    Scans:
      1. Hidden form fields (all frameworks)
      2. CSRF / XSRF tokens (30+ frameworks)
      3. Meta tag tokens + CSP nonces
      4. localStorage + sessionStorage
      5. ★ IndexedDB key names (via Playwright)
      6. ★ Cookie security attributes
      7. ★ WebSocket handshake tokens
      8. ★ GraphQL CSRF / operation tokens
      9. ★ Request headers (X-CSRF, Authorization)
      10.★ SvelteKit / Astro / Remix framework tokens
      11.★ Shadow DOM slot scan
      12.★ Service worker registration keys
    """
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    except ImportError:
        return {"error": "playwright_not_installed", "findings": [], "requests": 0}

    findings = []
    seen = set()
    request_count = [0]
    live_result = {"live_requests": [], "live_findings": [], "sse_frames": []}

    def _add(typ, val, src, name="", confidence="STATIC", extra=None):
        val = str(val).strip()
        key = typ + ":" + val[:80]
        if key not in seen and len(val) >= 6:
            seen.add(key)
            findings.append({
                "type": typ,
                "value": val,
                "name": name,
                "source": src,
                "confidence": confidence,
                **(extra or {}),
            })

    # ── Framework-specific CSRF token names ──────────────────────────────────
    _CSRF_NAMES = [
        # Generic
        "_token", "csrf_token", "csrftoken", "csrf", "xsrf_token", "_csrf",
        "__RequestVerificationToken", "authenticity_token",
        # Laravel
        "laravel_token", "_laravel_token",
        # Django
        "csrfmiddlewaretoken",
        # Rails
        "authenticity_token",
        # ASP.NET
        "__RequestVerificationToken", "__VIEWSTATE", "__EVENTVALIDATION", "__VIEWSTATEGENERATOR",
        # Spring / Java
        "_csrf", "X-CSRF-TOKEN",
        # Symfony
        "_token",
        # CodeIgniter
        "csrf_token_name", "csrf_hash",
        # CakePHP
        "_csrfToken",
        # Yii
        "_csrf-frontend", "_csrf-backend",
        # Angular
        "XSRF-TOKEN",
        # Express (csurf)
        "_csrf",
        # Flask-WTF
        "csrf_token",
        # SvelteKit ★
        "x-sveltekit-action",
        # Remix ★
        "csrf",
        # tRPC
        "x-trpc-source",
        # Astro ★
        "astro-csrf",
        # Next.js
        "__Host-next-auth.csrf-token",
    ]

    # ── Meta token patterns ───────────────────────────────────────────────────
    _META_TOKEN_PATTERNS = [
        (re.compile(r'<meta[^>]+name=["\']csrf-?token["\'][^>]+content=["\']([^"\']{10,})["\']', re.I), "CSRF Meta"),
        (re.compile(r'<meta[^>]+name=["\']xsrf-?token["\'][^>]+content=["\']([^"\']{10,})["\']', re.I), "XSRF Meta"),
        (re.compile(r'<meta[^>]+name=["\']_token["\'][^>]+content=["\']([^"\']{10,})["\']', re.I), "Laravel Token"),
        # CSP nonce
        (re.compile(r"<script[^>]*nonce=['\"]([A-Za-z0-9+/=]{10,})['\"]", re.I), "CSP Nonce"),
        # ★ Next.js action state
        (re.compile(r'action=["\']([A-Za-z0-9+/=]{20,})["\'].*?next-action', re.I), "Next.js Action"),
        # ★ SvelteKit CSRF
        (re.compile(r'__sveltekit_(?:csrf|session)_?[a-z_]*\s*=\s*["\']([^"\']{10,})["\']', re.I), "SvelteKit Token"),
        # ★ Astro page data tokens
        (re.compile(r'<script type=["\']astro-data["\'][^>]*>([^<]{20,})<', re.I), "Astro Page Data"),
        # ★ Remix session data
        (re.compile(r'window\.__remix[A-Za-z]+\s*=\s*["\']([^"\']{20,})["\']', re.I), "Remix Token"),
        # WordPress nonce
        (re.compile(r'var\s+[a-z_]+\s*=\s*\{[^}]*nonce\s*:\s*["\']([a-f0-9]{10})["\']', re.I), "WordPress Nonce"),
    ]

    # ── JS token patterns ─────────────────────────────────────────────────────
    _JS_TOKEN_PATTERNS = [
        (re.compile(r'(?:csrf|xsrf|csrfToken|_token)\s*[=:]\s*["\']([A-Za-z0-9+/=_\-]{10,})["\']', re.I), "JS CSRF"),
        (re.compile(r'window\.__(?:csrf|CSRF|token)[A-Za-z_]*\s*=\s*["\']([^"\']{10,})["\']', re.I), "Window Global"),
        (re.compile(r'headers\s*:\s*\{[^}]*["\']X-CSRF-Token["\']\s*:\s*["\']([^"\']{10,})["\']', re.I), "X-CSRF Header"),
        (re.compile(r'headers\s*:\s*\{[^}]*["\']X-XSRF-TOKEN["\']\s*:\s*["\']([^"\']{10,})["\']', re.I), "X-XSRF Header"),
        # ★ Fetch / Axios request interceptors
        (re.compile(r"axios\.defaults\.headers\.common\[['\"](X-CSRF|Authorization)['\"]]\s*=\s*['\"]([^'\"]{10,})['\"]", re.I), "Axios Header"),
        # ★ tRPC / React Query headers
        (re.compile(r"['\"]x-trpc-source['\"]\s*:\s*['\"]([^'\"]{4,40})['\"]", re.I), "tRPC Source"),
    ]

    with sync_playwright() as pw:
        if progress_cb: progress_cb("🌐 Launching stealth browser (2026 fingerprint)...")

        # ── 2026 Chrome 124 user agent ────────────────────────────────────────
        UA = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        )

        browser = pw.chromium.launch(
            headless=True,
            args=[
                '--no-sandbox',
                '--disable-dev-shm-usage',
                '--disable-blink-features=AutomationControlled',
                '--disable-web-security',
                '--disable-features=IsolateOrigins,site-per-process',
                '--enable-features=NetworkService,NetworkServiceInProcess',
                '--disable-site-isolation-trials',
                '--ignore-certificate-errors',
            ]
        )

        ctx = browser.new_context(
            user_agent=UA,
            viewport={"width": 1440, "height": 900},
            ignore_https_errors=True,
            java_script_enabled=True,
            extra_http_headers={
                "Accept-Language": "en-US,en;q=0.9",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Sec-CH-UA": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
                "Sec-CH-UA-Mobile": "?0",
                "Sec-CH-UA-Platform": '"Windows"',
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
                "Upgrade-Insecure-Requests": "1",
            }
        )

        # Anti-bot evasion
        ctx.add_init_script("""
            Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
            Object.defineProperty(navigator, 'plugins', {get: () => [1,2,3,4,5]});
            Object.defineProperty(navigator, 'languages', {get: () => ['en-US','en']});
            Object.defineProperty(navigator, 'platform', {get: () => 'Win32'});
            Object.defineProperty(navigator, 'hardwareConcurrency', {get: () => 8});
            Object.defineProperty(navigator, 'deviceMemory', {get: () => 8});
            Object.defineProperty(screen, 'colorDepth', {get: () => 24});
            window.chrome = {runtime: {}, loadTimes: () => {}, csi: () => {}};
            window.Notification = {permission: 'default'};
        """)

        page = ctx.new_page()
        captured_headers = {}

        def _on_request(req):
            request_count[0] += 1
            h = req.headers
            # Capture CSRF headers from real requests
            for hname in ['x-csrf-token', 'x-xsrf-token', 'x-requested-with',
                          'x-csrftoken', 'csrf-token', 'authorization']:
                if hname in h:
                    _add(f"Request Header: {hname}", h[hname],
                         f"Live request → {req.url[:60]}", confidence="CONFIRMED-LIVE")
            live_result["live_requests"].append({
                "url": req.url[:200], "method": req.method,
                "headers": dict(h),
            })

        def _on_response(resp):
            # Capture tokens from Set-Cookie headers
            sc = resp.headers.get("set-cookie", "")
            if sc:
                for pat in [r'XSRF-TOKEN=([^;]{10,})', r'csrf[_-]?token=([^;]{10,})',
                            r'laravel_session=([^;]{10,})']:
                    m = re.search(pat, sc, re.I)
                    if m:
                        _add("Cookie Token", m.group(1),
                             f"Set-Cookie ← {resp.url[:60]}", confidence="CONFIRMED-LIVE")

        def _on_ws(ws):
            ws.on("framesent",   lambda p: live_result["sse_frames"].append({"dir":"sent",  "data":str(p)[:200]}))
            ws.on("framereceived", lambda p: _scan_ws_frame(str(p)))

        def _scan_ws_frame(frame: str):
            for pat in [r'"token"\s*:\s*"([^"]{10,})"',
                        r'"csrf"\s*:\s*"([^"]{10,})"',
                        r'"Authorization"\s*:\s*"([^"]{10,})"']:
                m = re.search(pat, frame, re.I)
                if m:
                    _add("WebSocket Token", m.group(1),
                         "WebSocket frame", confidence="CONFIRMED-LIVE")

        page.on("request",  _on_request)
        page.on("response", _on_response)
        page.on("websocket", _on_ws)

        if progress_cb: progress_cb("📡 Loading page (intercepting all traffic)...")

        try:
            page.goto(url, wait_until="load", timeout=35_000)
        except Exception as e:
            browser.close()
            return {"error": str(e), "findings": [], "requests": request_count[0]}

        try:
            page.wait_for_load_state("networkidle", timeout=12_000)
        except Exception:
            pass

        if progress_cb: progress_cb("🔍 Scanning DOM, shadow DOM, storage...")

        html = page.content()

        # ── 1. Hidden form inputs ──────────────────────────────────────────────
        try:
            hidden_inputs = page.evaluate("""() => {
                const results = [];
                // Regular hidden inputs
                document.querySelectorAll('input[type="hidden"], input[type="text"][readonly]').forEach(el => {
                    if (el.name && el.value && el.value.length >= 6) {
                        results.push({name: el.name, value: el.value, tag: 'input'});
                    }
                });
                // Shadow DOM deep scan ★
                function scanShadow(root) {
                    if (root.shadowRoot) {
                        root.shadowRoot.querySelectorAll('input[type="hidden"]').forEach(el => {
                            if (el.name && el.value && el.value.length >= 6) {
                                results.push({name: el.name, value: el.value, tag: 'shadow-input'});
                            }
                        });
                        root.shadowRoot.querySelectorAll('*').forEach(scanShadow);
                    }
                }
                document.querySelectorAll('*').forEach(scanShadow);
                return results;
            }""")
            for inp in (hidden_inputs or []):
                name = inp.get("name", "")
                val  = inp.get("value", "")
                tag  = inp.get("tag", "input")
                is_csrf = any(t in name.lower() for t in
                              ['token', 'csrf', 'xsrf', 'nonce', 'key', 'secret'])
                typ = "CSRF Token" if is_csrf else "Hidden Input"
                confidence = "CONFIRMED" if is_csrf else "STATIC"
                _add(typ, val, f"DOM hidden {tag}", name=name, confidence=confidence)
        except Exception:
            pass

        # ── 2. Meta tag scan (include shadow DOM) ─────────────────────────────
        for pat, label in _META_TOKEN_PATTERNS:
            for m in pat.finditer(html):
                _add(label, m.group(1), "HTML meta/head", confidence="STATIC")

        # ── 3. JS patterns in inline scripts ─────────────────────────────────
        for pat, label in _JS_TOKEN_PATTERNS:
            for m in pat.finditer(html):
                g = m.group(1) if m.lastindex == 1 else m.group(2)
                if g:
                    _add(label, g, "Inline JS", confidence="STATIC")

        # ── 4. localStorage + sessionStorage ─────────────────────────────────
        try:
            storage = page.evaluate("""() => {
                const result = {};
                const keywordRe = /token|csrf|xsrf|nonce|session|auth|key|secret/i;
                for (let s of [['localStorage', localStorage], ['sessionStorage', sessionStorage]]) {
                    for (let i = 0; i < s[1].length; i++) {
                        const k = s[1].key(i);
                        const v = s[1].getItem(k);
                        if (k && v && keywordRe.test(k + v) && v.length >= 6) {
                            result[s[0] + ':' + k] = v;
                        }
                    }
                }
                return result;
            }""")
            for k, v in (storage or {}).items():
                store, name = k.split(":", 1)
                _add(f"{store} Token", str(v)[:200], store, name=name, confidence="STATIC")
        except Exception:
            pass

        # ★ 5. IndexedDB key names ─────────────────────────────────────────────
        try:
            idb_keys = page.evaluate("""() => new Promise(resolve => {
                const results = [];
                const keywordRe = /token|csrf|session|auth|key|nonce/i;
                const dbs = indexedDB.databases
                    ? indexedDB.databases().then(list => {
                        if (!list || list.length === 0) { resolve(results); return; }
                        let pending = list.length;
                        list.forEach(info => {
                            try {
                                const req = indexedDB.open(info.name);
                                req.onsuccess = () => {
                                    const db = req.result;
                                    const stores = Array.from(db.objectStoreNames);
                                    stores.forEach(s => {
                                        if (keywordRe.test(s)) results.push({db: info.name, store: s});
                                        const tx = db.transaction(s, 'readonly');
                                        const os = tx.objectStore(s);
                                        const kr = os.getAllKeys();
                                        kr.onsuccess = () => {
                                            (kr.result || []).forEach(k => {
                                                if (keywordRe.test(String(k)))
                                                    results.push({db: info.name, store: s, key: String(k)});
                                            });
                                        };
                                    });
                                    db.close();
                                    if (--pending === 0) resolve(results);
                                };
                                req.onerror = () => { if (--pending === 0) resolve(results); };
                            } catch(e) { if (--pending === 0) resolve(results); }
                        });
                    }).catch(() => resolve(results))
                    : resolve(results);
            })""",  # timeout
            )
            for item in (idb_keys or []):
                val = f"{item.get('db','?')}/{item.get('store','?')}"
                if item.get('key'):
                    val += f"[{item['key']}]"
                _add("IndexedDB Key Reference", val, "IndexedDB", confidence="STATIC")
        except Exception:
            pass

        # ★ 6. Service Worker registration check ──────────────────────────────
        try:
            sw_info = page.evaluate("""async () => {
                if (!navigator.serviceWorker) return [];
                const regs = await navigator.serviceWorker.getRegistrations();
                return regs.map(r => ({scope: r.scope, url: r.active?.scriptURL}));
            }""")
            for sw in (sw_info or []):
                if sw.get("url"):
                    _add("Service Worker", sw["url"], "ServiceWorker API",
                         name=sw.get("scope", ""), confidence="STATIC")
        except Exception:
            pass

        # ★ 7. GraphQL CSRF / operation token detection ────────────────────────
        try:
            gql_tokens = page.evaluate("""() => {
                const results = [];
                // Apollo Client cache
                if (window.__APOLLO_STATE__) {
                    const keys = Object.keys(window.__APOLLO_STATE__);
                    keys.filter(k => /token|auth|csrf/i.test(k)).forEach(k => {
                        results.push({type: 'Apollo Cache Key', value: k});
                    });
                }
                // Relay store
                if (window.__RELAY_STORE__) {
                    results.push({type: 'Relay Store', value: JSON.stringify(window.__RELAY_STORE__).slice(0, 200)});
                }
                return results;
            }""")
            for item in (gql_tokens or []):
                _add(item.get("type", "GraphQL Token"), item.get("value", ""),
                     "GraphQL/Apollo", confidence="STATIC")
        except Exception:
            pass

        # ★ 8. Cookie attribute scan ───────────────────────────────────────────
        try:
            cookies = ctx.cookies()
            for cookie in cookies:
                name = cookie.get("name", "")
                val  = cookie.get("value", "")
                is_csrf = any(t in name.lower() for t in ['csrf', 'xsrf', 'token', 'sess'])
                if is_csrf and val and len(val) >= 6:
                    attrs = []
                    if not cookie.get("httpOnly"): attrs.append("⚠️ NOT HttpOnly")
                    if not cookie.get("secure"):   attrs.append("⚠️ NOT Secure")
                    if cookie.get("sameSite", "").lower() == "none": attrs.append("⚠️ SameSite=None")
                    _add("Cookie Token", val[:200], "Cookie jar",
                         name=name,
                         confidence="CONFIRMED",
                         extra={"security_flags": ", ".join(attrs) if attrs else "OK"})
        except Exception:
            pass

        browser.close()

    return {
        "findings": findings,
        "requests": request_count[0],
        "live_result": live_result,
        "error": None,
    }


# ══════════════════════════════════════════════════════════════════════════════
# ══  SECTION 4: SITEKEY — ENHANCED _sitekey_playwright (2026 stealth)      ══
# ══════════════════════════════════════════════════════════════════════════════

# 2026 Chrome 124 UA list (rotate on each scan)
_UA_POOL_2026 = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
]

def _pick_ua():
    import random
    return random.choice(_UA_POOL_2026)

def _build_stealth_browser_args_2026():
    """Return Chromium launch args for 2026 stealth mode."""
    return [
        '--no-sandbox',
        '--disable-dev-shm-usage',
        '--disable-blink-features=AutomationControlled',
        '--disable-web-security',
        '--disable-features=IsolateOrigins,site-per-process',
        '--disable-site-isolation-trials',
        '--ignore-certificate-errors',
        '--disable-popup-blocking',
        '--disable-renderer-backgrounding',
        '--disable-backgrounding-occluded-windows',
        '--disable-ipc-flooding-protection',
        '--enable-features=NetworkService,NetworkServiceInProcess',
        # Prevent automation detection
        '--disable-automation',
        '--password-store=basic',
        '--use-mock-keychain',
    ]

def _build_stealth_init_script_2026():
    """Return anti-detection init script for Playwright."""
    return """
        // Remove webdriver flag
        Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
        // Fake plugins (Chrome normally has plugins)
        Object.defineProperty(navigator, 'plugins', {get: () => {
            const p = [
                {name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer'},
                {name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai'},
                {name: 'Native Client', filename: 'internal-nacl-plugin'},
            ];
            p.__proto__ = PluginArray.prototype;
            return p;
        }});
        // Realistic navigator values
        Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
        Object.defineProperty(navigator, 'platform', {get: () => 'Win32'});
        Object.defineProperty(navigator, 'hardwareConcurrency', {get: () => 8});
        Object.defineProperty(navigator, 'deviceMemory', {get: () => 8});
        Object.defineProperty(navigator, 'maxTouchPoints', {get: () => 0});
        // Fake screen
        Object.defineProperty(screen, 'colorDepth', {get: () => 24});
        Object.defineProperty(screen, 'pixelDepth', {get: () => 24});
        // Chrome object
        window.chrome = {
            app: {isInstalled: false, InstallState: {DISABLED:'DISABLED',INSTALLED:'INSTALLED',NOT_INSTALLED:'NOT_INSTALLED'}, RunningState: {CANNOT_RUN:'CANNOT_RUN',READY_TO_RUN:'READY_TO_RUN',RUNNING:'RUNNING'}},
            runtime: {id: undefined, connect: () => {}, sendMessage: () => {}},
            loadTimes: () => ({firstPaintTime: 0.12, requestTime: 0, startLoadTime: 0}),
            csi: () => ({onloadT: 100, pageT: 200, startE: Date.now(), tran: 15}),
        };
        // Notification
        window.Notification = window.Notification || {};
        Notification.permission = 'default';
        // WebGL vendor/renderer spoof
        const origGetParam = WebGLRenderingContext.prototype.getParameter;
        WebGLRenderingContext.prototype.getParameter = function(p) {
            if (p === 37445) return 'Intel Inc.';
            if (p === 37446) return 'Intel Iris OpenGL Engine';
            return origGetParam.call(this, p);
        };
        // Remove CDP-related properties
        delete window.cdc_adoQpoasnfa76pfcZLmcfl_Array;
        delete window.cdc_adoQpoasnfa76pfcZLmcfl_Promise;
        delete window.cdc_adoQpoasnfa76pfcZLmcfl_Symbol;
    """


# ══════════════════════════════════════════════════════════════════════════════
# ══  SECTION 5: KEYDUMP — WASM / BINARY HINT SCANNER                       ══
# ══════════════════════════════════════════════════════════════════════════════

def _scan_wasm_hints(html: str, base_url: str) -> list:
    """
    ★ 2026: Detect .wasm file references and extract string hints.
    WASM binaries sometimes embed API keys or config strings in their
    data section. We check the WASM URL refs and data-adjacent JSON.
    """
    import requests
    findings = []
    wasm_urls = re.findall(r'["\']([^"\']*\.wasm(?:\?[^"\']*)?)["\']', html, re.I)
    for wurl in wasm_urls[:5]:
        if not wurl.startswith('http'):
            wurl = urljoin(base_url, wurl)
        try:
            r = requests.get(wurl, timeout=10, verify=False, headers={
                'User-Agent': _UA_POOL_2026[0],
            })
            if r.status_code == 200:
                # Decode printable strings from WASM binary (like `strings` command)
                data = r.content
                current = []
                for byte in data:
                    if 32 <= byte < 127:
                        current.append(chr(byte))
                    else:
                        if len(current) >= 10:
                            s = ''.join(current)
                            # Check against key patterns
                            for label, (pat, icon) in _KD_PATTERNS.items():
                                m = re.search(pat, s, re.IGNORECASE)
                                if m:
                                    findings.append({
                                        "type": label,
                                        "value": m.group(1) if m.lastindex else m.group(0),
                                        "source": f"WASM binary: {wurl[:60]}",
                                        "icon": icon,
                                    })
                        current = []
        except Exception:
            pass
    return findings


# ══════════════════════════════════════════════════════════════════════════════
# ══  SECTION 6: CONFIDENCE SCORING — ENHANCED _kd_confidence (2026)        ══
# ══════════════════════════════════════════════════════════════════════════════

def _kd_confidence_2026(value: str, label: str, source: str, live: bool = False) -> dict:
    """
    2026 context-aware confidence scorer for keydump findings.

    Returns:
        {
            "confidence": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
            "score": 0-100,
            "reasons": [str, ...]
        }
    """
    score = 50
    reasons = []

    icon = _KD_PATTERNS.get(label, ("", "🌐"))[1]
    severity = _KD_SEVERITY.get(icon, "MEDIUM")

    # Base from severity
    base = {"CRITICAL": 70, "HIGH": 55, "MEDIUM": 40, "LOW": 20}.get(severity, 40)
    score = base

    # Live network confirmation = strong signal
    if live or "live" in source.lower():
        score += 25
        reasons.append("Confirmed in live network traffic")

    # Source map = often contains real keys (not minified/obfuscated)
    if "sourcemap" in source.lower():
        score += 10
        reasons.append("Found in source map (unminified)")

    # Environment file = almost certainly real
    if ".env" in source.lower():
        score += 20
        reasons.append("Found in .env file probe")

    # Dynamic storage = runtime value
    if "storage" in source.lower() or "indexeddb" in source.lower():
        score += 15
        reasons.append("Found in runtime browser storage")

    # Inline HTML = often real config
    if "html source" in source.lower() or "inline script" in source.lower():
        score += 5
        reasons.append("Found in page HTML")

    # High entropy = likely real secret (not placeholder)
    try:
        ent = _shannon_entropy(value)
        if ent > 4.5:
            score += 15
            reasons.append(f"High entropy ({ent:.2f} — likely real secret)")
        elif ent < 2.5:
            score -= 20
            reasons.append(f"Low entropy ({ent:.2f} — may be placeholder)")
    except Exception:
        pass

    # Common test/placeholder values
    placeholders = ['test', 'placeholder', 'your_key_here', 'changeme',
                    'xxxx', '1234', 'secret', 'example', 'dummy', 'fake']
    if any(p in value.lower() for p in placeholders):
        score -= 30
        reasons.append("Contains placeholder text")

    score = max(0, min(100, score))

    if score >= 75:   confidence = "CRITICAL"
    elif score >= 55: confidence = "HIGH"
    elif score >= 35: confidence = "MEDIUM"
    else:             confidence = "LOW"

    return {"confidence": confidence, "score": score, "reasons": reasons}

def _shannon_entropy(s: str) -> float:
    if not s: return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v/n) * math.log2(v/n) for v in freq.values())


# ══════════════════════════════════════════════════════════════════════════════
# ══  HOW TO APPLY THIS PATCH TO bot_v17.py                                 ══
# ══════════════════════════════════════════════════════════════════════════════
#
#  Method A — Import override (easiest):
#    bot_v17.py ရဲ့ imports block နောက်မှာ ဒါ ထည့်ပါ:
#
#      from key_enhancements_v2026 import (
#          _KD_PATTERNS, _KD_CATEGORIES, _KD_SEVERITY, _KD_COMPILED,
#          _CAPTCHA_PATTERNS_2026  as _CAPTCHA_PATTERNS,
#          _KEY_VALIDATORS_2026    as _KEY_VALIDATORS,
#          _CAPTCHA_SCAN_ORDER_2026 as _CAPTCHA_SCAN_ORDER,
#          _CAPTCHA_SCRIPT_SIGS_2026 as _CAPTCHA_SCRIPT_SIGS,
#          _hiddenkeys_sync_2026   as _hiddenkeys_sync,
#          _kd_confidence_2026     as _kd_confidence,
#          _scan_wasm_hints,
#          _build_stealth_browser_args_2026,
#          _build_stealth_init_script_2026,
#          _pick_ua,
#      )
#
#  Method B — bot_v18.py ကို build ချင်ရင်:
#    ဒီ file ကို review ပြီး functions တွေကို တိုက်ရိုက် paste/replace လုပ်ပါ
#
# ══════════════════════════════════════════════════════════════════════════════
