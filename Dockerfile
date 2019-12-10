FROM python:3.7-slim
LABEL maintainer="Charlie Lewis <clewis@iqt.org>"

COPY requirements.txt requirements.txt

ENV DEBIAN_FRONTEND=noninteractive
ENV BUILD_DEPS="gcc git"

RUN apt-get update && apt-get install -yq --no-install-recommends \
    $BUILD_DEPS \
    tshark \
    && pip3 install --no-cache-dir --upgrade pip==19.3.1 \
    && pip3 install wheel==0.33.6 \
    && pip3 install --no-cache-dir -r requirements.txt\
    && apt-get remove --purge --auto-remove -y $BUILD_DEPS \
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
