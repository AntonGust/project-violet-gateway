FROM nginxinc/nginx-unprivileged:1.27-alpine@sha256:65e3e85dbaed8ba248841d9d58a899b6197106c23cb0ff1a132b7bfe0547e4c0

RUN rm /etc/nginx/conf.d/default.conf

COPY nginx.conf.template /etc/nginx/templates/default.conf.template

EXPOSE 8080

# nginx docker image runs envsubst on /etc/nginx/templates/*.template
# and writes results to /etc/nginx/conf.d/ on startup.
# Required env vars: LLM_BACKEND, LLM_API_KEY
