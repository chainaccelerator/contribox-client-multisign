# Docker images

Images are base on ubuntu (focal).
Default version is `0.8.0`.
  > --build-args LIBWALLY_CORE_VERSION=0.8.0

## Builder image

Contains the build environement for libwally-core with source.

  > build -f ubuntu/libwally-core.dockerfile . -t libwally-core:0.8.0-ubuntu

## Native libraries

  > docker build -f ubuntu/libwally-core.dockerfile . -t libwally-core:0.8.0-ubuntu

## Python binding

  > docker build -f ubuntu/wallycore.dockerfile . -t wallycore:0.8.0-ubuntu

## TL;DR

> make && make server
