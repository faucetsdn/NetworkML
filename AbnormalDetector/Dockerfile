FROM python:3.5
MAINTAINER Cory Stephenson <cstephenson@iqt.org>

RUN apt-get update && apt-get install -y \
    tcpdump

RUN pip install numpy redis scipy tensorflow 
WORKDIR /app/AbnormalDetector
