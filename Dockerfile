FROM ubuntu:latest
ARG TOKEN

# Copy files
COPY ./src /home/pro/

# Update apt repository and install dependencies
RUN apt -y update && \
    apt install -y \
    libpcap-dev \
    python3 \
    python3-pip \
    masscan \
    git \
    nmap \
    python3-dev && \
    mkdir /home/pro/data && \
    pip3 install setuptools \
    beautifulsoup4 && \
    pip3 install git+https://$TOKEN:x-oauth-basic@github.com/sofahd/sofahutils.git

WORKDIR /home/api

CMD python3 /home/pro/startup.py
