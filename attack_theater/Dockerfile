FROM python:3.12-slim@sha256:46cb7cc2877e60fbd5e21a9ae6115c30ace7a077b9f8772da879e4590c18c2e3 AS base

RUN addgroup --system --gid 1000 theater \
 && adduser --system --uid 1000 --gid 1000 --no-create-home theater

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ---- vendor xterm.js (offline capable) ----
RUN mkdir -p static/vendor/xterm && python - <<'EOF'
import urllib.request, pathlib, sys
OUT  = pathlib.Path("static/vendor/xterm")
URLS = {
    "xterm.js":  "https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.js",
    "xterm.css": "https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.css",
}
for fname in URLS:
    try:
        urllib.request.urlretrieve(URLS[fname], OUT / fname)
        print(f"Downloaded {fname}")
    except Exception as e:
        print(f"WARNING: could not download {fname}: {e}", file=sys.stderr)
EOF

COPY app/     ./app/
COPY static/  ./static/

RUN mkdir -p /data && chown theater:theater /data

USER theater

EXPOSE 8080

CMD ["python", "-m", "app.main"]
