FROM python:3.5
LABEL maintainer="Charlie Lewis <clewis@iqt.org>"

RUN apt-get update && apt-get install -y \
    tcpdump

RUN pip install numpy==1.13.3 \
                redis==2.10.6 \
                scikit-learn==0.18.2 \
                scipy==1.0.0 \
                pika==0.11.0 \
                tensorflow==1.3.0

COPY NodeClassifier /NodeClassifier
WORKDIR /NodeClassifier

COPY scripts /scripts
WORKDIR /scripts

ENTRYPOINT ["./run", "onelayer"]
CMD ["eval"]
