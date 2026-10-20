FROM python:3.11-alpine

RUN apk add --no-cache curl iproute2 procps && \
    addgroup -g 10001 sandbox && \
    adduser -D -u 10001 -G sandbox -h /workspace sandbox && \
    mkdir -p /workspace && \
    chown -R 10001:10001 /workspace

# Ensure no SUID/SGID bits exist inside the hardened container image
RUN find / -xdev -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true

USER 10001:10001
WORKDIR /workspace

CMD ["python3", "-c", "print('sandbox-ready')"]
