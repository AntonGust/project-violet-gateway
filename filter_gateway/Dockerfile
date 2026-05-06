FROM haproxy:2.9-alpine@sha256:3e29449a6beed63262e36104adf531b4e41b359f61937303f5ea8607987b3748

USER root

# Install Python for the sidecar + Lua socket for HAProxy
RUN apk add --no-cache python3 py3-pip lua5.3 lua5.3-socket bash

# Dedicated non-root user shared by HAProxy and the sidecar.
# Both processes run as this user so the 0o600 Unix socket is accessible to both.
RUN addgroup -S filter && adduser -S filter -G filter

# Create app directories with correct ownership
RUN mkdir -p /app/sidecar /data && chown -R filter:filter /app /data

# Copy HAProxy config
COPY haproxy.cfg /usr/local/etc/haproxy/haproxy.cfg
COPY filter_check.lua /usr/local/etc/haproxy/filter_check.lua

# Copy sidecar
COPY sidecar/ /app/sidecar/

# Copy entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

USER filter

EXPOSE 2222

ENTRYPOINT ["/entrypoint.sh"]
