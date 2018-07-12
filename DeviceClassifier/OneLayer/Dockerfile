FROM cyberreboot/poseidonml:base
LABEL maintainer="Charlie Lewis <clewis@iqt.org>"

COPY . /OneLayer
COPY models /models
WORKDIR /OneLayer

ENTRYPOINT ["python3", "eval_OneLayer.py"]
