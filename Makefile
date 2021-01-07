.DEFAULT_GOAL := build
LIBWALLY_VERSION?=0.8.1

build:
	docker build -f wasm-module/docker/libwally-core-builder.dockerfile --build-arg=LIBWALLY_CORE_VERSION=$(LIBWALLY_VERSION) . -t libwally-wasm:${LIBWALLY_VERSION}
	# docker build --no-cache -f wasm-module/docker/libwally-core-builder.dockerfile --build-arg=LIBWALLY_CORE_VERSION=$(LIBWALLY_VERSION) . -t libwally-wasm:${LIBWALLY_VERSION}

test:
	docker build -f wasm-module/docker/libwally-core-test.dockerfile --build-arg=LIBWALLY_CORE_VERSION=$(LIBWALLY_VERSION) . -t libwally-wasm-test:${LIBWALLY_VERSION}
	# docker build --no-cache -f wasm-module/docker/libwally-core-test.dockerfile --build-arg=LIBWALLY_CORE_VERSION=$(LIBWALLY_VERSION) . -t libwally-wasm-test:${LIBWALLY_VERSION}

bin:
	mkdir ./bin
	docker create --name libwally libwally-wasm:${LIBWALLY_VERSION}
	docker cp libwally:/src/contribox/contribox.wasm ./bin/
	docker cp libwally:/src/contribox/contribox.js ./bin/
	docker rm libwally

clean:
	docker rmi -f libwally-wasm:${LIBWALLY_VERSION}
	docker rmi -f libwally-wasm-test:${LIBWALLY_VERSION}

deep-clean:
	yes | docker system prune --all

.PHONY: build clean builder deep-clean test
