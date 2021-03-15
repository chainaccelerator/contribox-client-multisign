FROM debian:buster-slim

ARG LIBWALLY_CORE_VERSION

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
    apt-transport-https

RUN git clone https://github.com/ElementsProject/libwally-core.git -b release_$LIBWALLY_CORE_VERSION /src/contribox/libwally
WORKDIR /src/contribox/libwally
RUN git submodule init && \
    git submodule sync --recursive && \
    git submodule update --init --recursive

ARG PYTHON_VERSION=3
RUN ./tools/cleanup.sh && ./tools/autogen.sh
SHELL [ "/bin/bash", "-c" ]
ARG CFLAGS="-fno-stack-protector"
RUN ./configure \
    --build=$HOST_OS \
    ac_cv_c_bigendian=no \
    --disable-swig-python \
    --disable-swig-java \
    --enable-elements \
    --disable-ecmult-static-precomputation \
    --disable-tests \
    --disable-shared \
    --enable-export-all 
RUN make -j$(nproc)
ADD crypto-node/ /src/contribox
WORKDIR /src/contribox
RUN ./tools/autogen.sh
RUN ./configure 
RUN gcc \
    -D BUILD_ELEMENTS=1 \
    src/crypto.c \
    src/util.c \
    src/contribox.c \
    -Llibwally/src/.libs -lwallycore \
    -Llibwally/src/secp256k1/.libs -lsecp256k1 \
    -o crypto_node
ENTRYPOINT [ "./crypto_node" ]
