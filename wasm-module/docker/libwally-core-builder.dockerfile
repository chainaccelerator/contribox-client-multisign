FROM debian:buster

RUN apt-get update && apt-get install -yqq git \
    uncrustify \
    python3-distutils-extra \
    python3-dev \
    build-essential \
    libffi-dev \
    autoconf \
    libtool \
    pkg-config \
    lib32z1 \
    unzip \
    curl \
    lib32z1 \
    virtualenv \
    python3-setuptools \
    apt-transport-https

RUN git clone https://github.com/emscripten-core/emsdk.git /src/emsdk

WORKDIR /src/emsdk
RUN ./emsdk install latest && ./emsdk activate latest

RUN git clone https://github.com/ElementsProject/libwally-core.git /src/libwally
WORKDIR /src/libwally
RUN git submodule init && \
    git submodule sync --recursive && \
    git submodule update --init --recursive

ARG PYTHON_VERSION=3
RUN /bin/bash -c '. /src/emsdk/emsdk_env.sh && ./tools/build_wasm.sh --enable-elements'
