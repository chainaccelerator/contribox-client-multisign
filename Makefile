.DEFAULT_GOAL := build
# LIBWALLY_VERSION?=0.8.0
# ELEMENTS_VERSION?=0.18.1.8

build:
	docker build -f wasm-module/docker/libwally-core-builder.dockerfile . -t libwally-wasm:dirty
	# docker build --no-cache -f wasm-module/docker/libwally-core-builder.dockerfile . -t libwally-wasm:dirty

clean:
	docker rmi -f libwally-wasm:dirty

deep-clean:
	yes | docker system prune --all

.PHONY: build clean builder 
