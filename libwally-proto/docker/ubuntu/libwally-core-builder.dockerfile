FROM ubuntu:focal

ARG LIBWALLY_CORE_VERSION

RUN apt-get update && apt-get install -y git
RUN git clone https://github.com/ElementsProject/libwally-core.git -b release_$LIBWALLY_CORE_VERSION /src/libwally


WORKDIR /src/libwally
RUN DEBIAN_FRONTEND=noninteractive contrib/ubuntu_deps.sh

