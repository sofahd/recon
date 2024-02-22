FROM ubuntu:latest
ARG TOKEN
ARG LOG_API

# Set environment variables
ENV LOG_API=$LOG_API
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

WORKDIR /home/pro

CMD python3 /home/pro/startup.py
