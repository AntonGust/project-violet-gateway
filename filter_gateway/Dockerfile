FROM haproxy:2.9-alpine

USER root

# Install Python for the sidecar + Lua socket for HAProxy
RUN apk add --no-cache python3 py3-pip lua5.3 lua5.3-socket bash

# Create app directories
RUN mkdir -p /app/sidecar /data /tmp

# Copy HAProxy config
COPY haproxy.cfg /usr/local/etc/haproxy/haproxy.cfg
COPY filter_check.lua /usr/local/etc/haproxy/filter_check.lua

# Copy sidecar
COPY sidecar/ /app/sidecar/

# Copy entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 2222

ENTRYPOINT ["/entrypoint.sh"]
