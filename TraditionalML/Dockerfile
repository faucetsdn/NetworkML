FROM python:3.5
MAINTAINER Charlie Lewis <clewis@iqt.org>

RUN apt-get update && apt-get install -y \
    tcpdump

RUN pip install numpy scikit-learn scipy
RUN pip install redis
COPY . /TraditionalML
WORKDIR /TraditionalML

ENTRYPOINT ["python3.5", "eval_OneLayer.py"]
CMD [""]
