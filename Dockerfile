FROM python:3.7-slim
LABEL maintainer="Charlie Lewis <clewis@iqt.org>"

COPY requirements.txt requirements.txt

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gcc \
    git \
    python3 \
    python3-dev \
    tcpdump \
    && pip3 install --no-cache-dir --upgrade pip==19.3.1 \
    && pip3 install wheel \
    && pip3 install --no-cache-dir -r requirements.txt\
    && apt-get remove --purge --auto-remove -y curl gcc git python3-dev \
    && apt-get clean \
    && apt-get autoclean \
    && apt-get autoremove \
    && rm -rf /tmp/* /var/tmp/* \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /var/cache/apt/archives/*.deb \
        /var/cache/apt/archives/partial/*.deb \
        /var/cache/apt/*.bin \
    && rm -rf /root/.[acpw]*

COPY . /networkml
WORKDIR /networkml
RUN pip3 install .
ENTRYPOINT ["networkml"]
