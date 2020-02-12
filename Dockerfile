FROM alpine:3.10
LABEL maintainer="Charlie Lewis <clewis@iqt.org>"

ENV PYTHONUNBUFFERED 1
COPY requirements.txt requirements.txt

RUN apk upgrade --no-cache && \
    apk add --no-cache \
    build-base \
    cython \
    gcc \
    git \
    libxml2-dev \
    libxslt-dev \
    python3 \
    python3-dev \
    py3-numpy \
    py3-scipy \
    py3-setuptools \
    tshark && \
    pip3 install --no-cache-dir --upgrade pip==20.0.2 && \
    pip3 install --no-cache-dir --upgrade -r requirements.txt && \
    apk del build-base \
    cython \
    gcc \
    git \
    libxml2-dev \
    libxslt-dev \
    python3-dev && \
    rm -rf /var/cache/* && \
    rm -rf /root/.cache/*

COPY . /networkml
WORKDIR /networkml

RUN pip3 install .
ENTRYPOINT ["networkml"]
