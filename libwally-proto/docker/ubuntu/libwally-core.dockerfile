ARG LIBWALLY_CORE_VERSION

FROM libwally-core-builder:${LIBWALLY_CORE_VERSION}-ubuntu AS builder

## build libwally
RUN ./tools/autogen.sh

ENV PYTHON_VERSION=3
RUN ./configure --prefix=/stage/local --enable-elements --enable-static --enable-shared

RUN make &&\
    make check &&\
    make install


FROM ubuntu:focal

COPY --from=builder /stage/local /usr/local
