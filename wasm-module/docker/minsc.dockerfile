FROM rust:1.49-slim-buster

ARG MINSC_VERSION

RUN apt-get update && apt-get install git -yqq

RUN git clone https://github.com/Sosthene00/minsc.git -b ${MINSC_VERSION} /usr/src/minsc
# RUN git clone https://github.com/shesek/minsc.git -b ${MINSC_VERSION} /usr/src/minsc

WORKDIR /usr/src/minsc

RUN cargo build --release

RUN cp /usr/src/minsc/target/release/minsc /usr/local/bin/minsc
