FROM python:3.8-slim
LABEL maintainer="Charlie Lewis <clewis@iqt.org>"

ENV PYTHONUNBUFFERED 1
COPY requirements.txt requirements.txt

RUN apt-get update && apt-get install -y tshark && \
    pip3 install --no-cache-dir --upgrade -r base-requirements.txt && \
    rm -rf /var/cache/* && \
    rm -rf /root/.cache/*

COPY . /networkml
WORKDIR /networkml

RUN pip3 install .
ENTRYPOINT ["networkml"]

