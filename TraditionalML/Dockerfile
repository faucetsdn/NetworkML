FROM python:3.5
MAINTAINER Charlie Lewis <clewis@iqt.org>

RUN apt-get update && apt-get install -y \
    tcpdump

COPY . /TraditionalML
WORKDIR /TraditionalML
RUN pip install -r requirements.txt

ENTRYPOINT ["python3.5", "eval_LogReg.py"]
CMD [""]
