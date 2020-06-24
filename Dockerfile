FROM python:3.8-slim
LABEL maintainer="Charlie Lewis <clewis@iqt.org>"

ENV PYTHONUNBUFFERED 1
COPY requirements.txt requirements.txt

RUN apt-get update && apt-get install -y python3-numpy python3-scipy gfortran libblas-dev liblapack-dev libxslt-dev libxml2-dev flex bison zlib1g-dev tshark && \
#RUN apt-get update && apt-get install -y tshark && \
    pip3 install --no-cache-dir --upgrade -r requirements.txt && \
    apt-get remove -y libblas-dev liblapack-dev libxslt-dev libxml2-dev gfortran flex bison zlib1g-dev && \
    apt-get autoremove -y && \
    rm -rf /var/cache/* && \
    rm -rf /root/.cache/*

COPY . /networkml
WORKDIR /networkml

RUN pip3 install .
ENTRYPOINT ["networkml"]

