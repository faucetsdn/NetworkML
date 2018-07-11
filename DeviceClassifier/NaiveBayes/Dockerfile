FROM cyberreboot/poseidonml:base
LABEL maintainer="Charlie Lewis <clewis@iqt.org>"

COPY . /NaiveBayes
COPY models /models
WORKDIR /NaiveBayes

ENTRYPOINT ["python3"]
CMD ["eval_NaiveBayes.py"]
