FROM cyberreboot/networkml:base
LABEL maintainer="Charlie Lewis <clewis@iqt.org>"

ENV PYTHONUNBUFFERED 1
COPY requirements.txt requirements.txt

RUN pip3 install --no-cache-dir --upgrade -r requirements.txt

COPY . /networkml
WORKDIR /networkml

RUN pip3 install .
ENTRYPOINT ["networkml"]
