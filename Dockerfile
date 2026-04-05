# Playwright Chromium အတွက် official base image သုံး
FROM mcr.microsoft.com/playwright/python:v1.44.0-jammy

WORKDIR /app

# System deps (Playwright image မှာ အများစု ပါပြီး — extra ones ထပ်ထည့်)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libglib2.0-0 \
    libnss3 \
    libnspr4 \
    libdbus-1-3 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libatspi2.0-0 \
    libx11-6 \
    libxcomposite1 \
    libxdamage1 \
    libxext6 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libxcb1 \
    libxkbcommon0 \
    libpango-1.0-0 \
    libcairo2 \
    libasound2 \
    && rm -rf /var/lib/apt/lists/*

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Chromium browser install (image မှာ ပါပြီးသားဖြစ်နိုင်သည် — confirm install)
RUN playwright install chromium

# App files
COPY . .

# Downloads directory (Railway ephemeral storage)
RUN mkdir -p /root/downloads/web_sources \
             /root/downloads/resume_states \
             /root/downloads/app_analysis

CMD ["python", "web_downloader_bot_v17_fixed.py"]
