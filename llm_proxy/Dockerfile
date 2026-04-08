FROM nginx:1.27-alpine

RUN rm /etc/nginx/conf.d/default.conf

COPY nginx.conf.template /etc/nginx/templates/default.conf.template

EXPOSE 8080

# nginx docker image runs envsubst on /etc/nginx/templates/*.template
# and writes results to /etc/nginx/conf.d/ on startup.
# Required env vars: LLM_BACKEND, LLM_API_KEY
