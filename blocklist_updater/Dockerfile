FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    cron \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY update_blocklist.py /app/
COPY crontab /etc/cron.d/blocklist-cron
COPY entrypoint.sh /entrypoint.sh

RUN chmod 0644 /etc/cron.d/blocklist-cron && \
    crontab /etc/cron.d/blocklist-cron && \
    chmod +x /entrypoint.sh

RUN mkdir -p /data

ENTRYPOINT ["/entrypoint.sh"]
