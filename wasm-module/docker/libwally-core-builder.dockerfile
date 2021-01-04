FROM debian:buster

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

RUN git clone https://github.com/emscripten-core/emsdk.git /src/emsdk

WORKDIR /src/emsdk
RUN ./emsdk install latest && ./emsdk activate latest

RUN git clone https://github.com/ElementsProject/libwally-core.git -b release_$LIBWALLY_CORE_VERSION /src/contribox/libwally
WORKDIR /src/contribox/libwally
RUN git submodule init && \
    git submodule sync --recursive && \
    git submodule update --init --recursive

ARG PYTHON_VERSION=3
ENV SOURCE_EMSDK='. /src/emsdk/emsdk_env.sh'
RUN ./tools/cleanup.sh && ./tools/autogen.sh
SHELL [ "/bin/bash", "-c" ]
ARG CFLAGS="-fno-stack-protector"
RUN ${SOURCE_EMSDK} && emconfigure ./configure \
    --build=$HOST_OS \
    ac_cv_c_bigendian=no \
    --disable-swig-python \
    --disable-swig-java \
    --enable-elements \
    --disable-ecmult-static-precomputation \
    --disable-tests \
    --enable-export-all 
RUN ${SOURCE_EMSDK} && emmake make -j$(nproc)
ADD wasm-module/ /src/contribox
WORKDIR /src/contribox
RUN ./tools/autogen.sh
RUN ${SOURCE_EMSDK} && emconfigure ./configure 
ARG EXTRA_EXPORTED_RUNTIME_METHODS="['getValue', 'UTF8ToString', 'stringToUTF8', 'lengthBytesUTF8', 'cwrap', 'ccall']"
ARG EXPORTED_FUNCTIONS="[\
    '_malloc',\
    '_free',\
    '_wally_init',\
    '_wally_secp_randomize',\
    '_is_elements',\
    '_wally_free_string',\
    '_wally_asset_blinding_key_from_seed']"
RUN ${SOURCE_EMSDK} && emcc \
    -s "EXTRA_EXPORTED_RUNTIME_METHODS=$EXTRA_EXPORTED_RUNTIME_METHODS" \
    -s "EXPORTED_FUNCTIONS=$EXPORTED_FUNCTIONS" \
    -D BUILD_ELEMENTS=1 \
    src/contribox.c \
    -Llibwally/src/.libs -lwallycore \
    -Llibwally/src/secp256k1/.libs -lsecp256k1 \
    -o contribox.html \
    --shell-file contrib/shell_minimal.html
ENTRYPOINT [ "python3", "-m", "http.server" ]
