FROM iqtlabs/rbqwrapper:v0.11.31
LABEL maintainer="Charlie Lewis <clewis@iqt.org>"

ENV DEBIAN_FRONTEND "noninteractive"
ENV PYTHONUNBUFFERED 1
COPY requirements.txt requirements.txt

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y git python3-numpy python3-scipy gfortran libblas-dev liblapack-dev libxslt-dev libxml2-dev flex bison zlib1g-dev tshark && \
    pip3 install --no-cache-dir --upgrade -r requirements.txt && \
    apt-get remove -y libblas-dev liblapack-dev libxslt-dev libxml2-dev gfortran flex bison zlib1g-dev && \
    apt-get autoremove -y && \
    rm -rf /var/cache/* && \
    rm -rf /root/.cache/*

COPY . /networkml
WORKDIR /networkml

RUN pip3 install .
ENTRYPOINT ["/rbqwrapper.py", "networkml"]
