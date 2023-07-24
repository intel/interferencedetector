FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive
WORKDIR /
RUN apt update ; apt-get install apt-transport-https ca-certificates -y ; update-ca-certificates
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install --no-install-recommends -y \
    zip bison build-essential cmake flex git libedit-dev \
    libllvm12 llvm-12-dev libclang-12-dev python zlib1g-dev libelf-dev libfl-dev python3-setuptools \
    liblzma-dev arping netperf iperf linux-tools-generic python3-pip && rm -rf /var/lib/apt/lists/*
RUN rm /usr/bin/perf
RUN ln -s /usr/lib/linux-tools/*/perf /usr/bin/perf
RUN git clone https://github.com/iovisor/bcc.git
RUN mkdir bcc/build; cd bcc/build ; cmake .. ; make ; make install ; cmake -DPYTHON_CMD=python3 .. ; cd src/python/ ; make ; make install ; cd ../..
COPY procmon/ .
COPY requirements.txt .
RUN pip install -r requirements.txt