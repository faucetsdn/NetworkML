FROM iqtlabs/rbqwrapper:v0.11.33
LABEL maintainer="Charlie Lewis <clewis@iqt.org>"

ENV DEBIAN_FRONTEND "noninteractive"
ENV PYTHONUNBUFFERED 1
ENV PATH="${PATH}:/root/.local/bin"
COPY pyproject.toml pyproject.toml

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y git python3-numpy python3-scipy gfortran libblas-dev liblapack-dev libxslt-dev libxml2-dev flex bison zlib1g-dev tshark curl && \
    apt-get remove -y libblas-dev liblapack-dev libxslt-dev libxml2-dev gfortran flex bison zlib1g-dev && \
    apt-get autoremove -y && \
    rm -rf /var/cache/* && \
    rm -rf /root/.cache/* && \
    curl -sSL https://install.python-poetry.org | python3 - && \
    poetry config virtualenvs.create false && \
    pip install -U pip

COPY . /networkml
WORKDIR /networkml
RUN poetry install
ENTRYPOINT ["/rbqwrapper.py", "networkml"]
