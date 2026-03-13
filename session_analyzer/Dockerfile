FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    inotify-tools \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -r -s /bin/false analyzer

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . /app/

RUN mkdir -p /data && chown analyzer:analyzer /data

USER analyzer

ENTRYPOINT ["python", "analyzer.py"]
