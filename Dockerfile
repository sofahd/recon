FROM ubuntu:22.04
ARG LOG_API

# Set environment variables
ENV LOG_API=$LOG_API
RUN export DEBIAN_FRONTEND=noninteractive

# Copy files
COPY ./src /home/pro/

# Update apt repository and install dependencies
RUN apt -y update && \
    apt install -y \
    libpcap-dev \
    libcap2-bin \
    python3 \
    python3-pip \
    masscan \
    git \
    nmap \
    python3-dev
RUN mkdir /home/pro/data
RUN pip3 install setuptools \
    pyOpenSSL \
    beautifulsoup4 && \
    pip3 install git+https://github.com/sofahd/sofahutils.git

# Drop root: recon runs as an unprivileged user. masscan brings its own TCP/IP stack and
# needs raw sockets, so grant CAP_NET_RAW on the binary itself (a file capability) rather
# than to the whole container -- the container only has to keep NET_RAW in its bounding set
# (see the service_def's cap_add). nmap needs nothing: unprivileged it falls back to a TCP
# connect scan, which is all -sV --script=banner requires here.
RUN groupadd -g 2000 pro && \
    useradd -u 2000 -g 2000 -d /home/pro -s /bin/bash pro && \
    setcap cap_net_raw+ep "$(command -v masscan)" && \
    chown -R pro:pro /home/pro

WORKDIR /home/pro
USER pro:pro

CMD python3 /home/pro/startup.py
