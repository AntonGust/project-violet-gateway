FROM python:3.12-slim@sha256:46cb7cc2877e60fbd5e21a9ae6115c30ace7a077b9f8772da879e4590c18c2e3

RUN addgroup --system --gid 1001 analyst \
 && adduser --system --uid 1001 --gid 1001 --no-create-home analyst

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY agent/ ./agent/

RUN mkdir -p /data/reports && chown analyst:analyst /data /data/reports

USER analyst

CMD ["python", "-m", "agent.main"]
