FROM python:3.11-slim@sha256:6d85378d88a19cd4d76079817532d62232be95757cb45945a99fec8e8084b9c2

# No cron daemon needed — scheduling is handled inside the Python process.
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY update_blocklist.py /app/

RUN addgroup --system blocklist && adduser --system --ingroup blocklist blocklist && \
    mkdir -p /data && chown blocklist:blocklist /data

USER blocklist

CMD ["python", "/app/update_blocklist.py", "--loop"]
