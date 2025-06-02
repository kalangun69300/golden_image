FROM python:3.11.12-alpine3.21

RUN addgroup -g 1002 userapp && \
    adduser -u 1002 -G userapp -h /home/appuser -s /bin/bash -D appuser

WORKDIR /app

RUN apk update && \
    apk add --no-cache \
        bluez-dev \
        tk-dev \
        util-linux-dev \
        curl \
        bash && \
    pip install --no-cache-dir --upgrade "setuptools>=78.1.1"

USER userapp

CMD ["python3"]

HEALTHCHECK --interval=30s --timeout=5s \
  CMD pgrep -x python3 > /dev/null || exit 1
