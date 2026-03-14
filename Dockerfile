FROM python:3.8-alpine

LABEL maintainer="Will Fantom <w.fantom@lancs.ac.uk>"
LABEL description="Ryū SDN Framework v4.30 with modular SDN security testbed"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/ryu-apps

RUN apk add --no-cache \
    ca-certificates \
    libffi \
    libgcc \
    libstdc++ \
    libxml2 \
    libxslt \
    openssl \
    tcpdump \
    zlib && \
    apk add --no-cache --virtual .build-dependencies \
    gcc \
    git \
    libffi-dev \
    libxslt-dev \
    libxml2-dev \
    make \
    musl-dev \
    openssl-dev \
    zlib-dev

WORKDIR /root

COPY requirements.txt /tmp/requirements.txt

RUN pip install --no-cache-dir -r /tmp/requirements.txt && \
    git clone https://github.com/osrg/ryu.git && \
    cd ryu && \
    git checkout tags/v4.30 && \
    pip install --no-cache-dir . && \
    rm -f /tmp/requirements.txt

WORKDIR /ryu-apps

COPY . /ryu-apps

RUN chmod +x /ryu-apps/attacks/*.sh /ryu-apps/experiments/*.sh /ryu-apps/scripts/*.sh /ryu-apps/traffic/*.sh && \
    apk del .build-dependencies && \
    rm -rf /var/cache/apk/* && \
    rm -rf /root/.cache/pip/*

EXPOSE 6633 8080

CMD ["ryu-manager", "controller.main"]
