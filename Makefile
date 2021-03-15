.DEFAULT_GOAL := build
LIBWALLY_VERSION?=0.8.2
MINSC_VERSION?=master

build:
	docker build -f wasm-module/docker/libwally-core-builder.dockerfile --build-arg=LIBWALLY_CORE_VERSION=$(LIBWALLY_VERSION) . -t libwally-wasm:${LIBWALLY_VERSION}
	# docker build --no-cache -f wasm-module/docker/libwally-core-builder.dockerfile --build-arg=LIBWALLY_CORE_VERSION=$(LIBWALLY_VERSION) . -t libwally-wasm:${LIBWALLY_VERSION}
	
crypto_node:
	docker build -f crypto-node/docker/libwally-core-builder.dockerfile --build-arg=LIBWALLY_CORE_VERSION=$(LIBWALLY_VERSION) . -t libwally-node:${LIBWALLY_VERSION}

test:
	docker build -f wasm-module/docker/libwally-core-test.dockerfile --build-arg=LIBWALLY_CORE_VERSION=$(LIBWALLY_VERSION) . -t libwally-wasm-test:${LIBWALLY_VERSION}
	# docker build --no-cache -f wasm-module/docker/libwally-core-test.dockerfile --build-arg=LIBWALLY_CORE_VERSION=$(LIBWALLY_VERSION) . -t libwally-wasm-test:${LIBWALLY_VERSION}

bin:
	mkdir ./bin
	docker create --name libwally libwally-wasm:${LIBWALLY_VERSION}
	docker cp libwally:/src/contribox/contribox.wasm ./bin/
	docker cp libwally:/src/contribox/contribox.js ./bin/
	docker cp libwally:/src/contribox/contribox.html ./bin/
	docker cp libwally:/src/contribox/main.js ./bin/
	docker rm libwally
minsc-bin:
	mkdir ./minsc_bin
	docker create --name minsc minsc-wasm:${MINSC_VERSION}
	docker cp minsc:/usr/local/bin/minsc ./minsc_bin/minsc
	docker rm minsc

minsc: 
	docker build -f wasm-module/docker/minsc.dockerfile --build-arg=MINSC_VERSION=$(MINSC_VERSION) . -t minsc-wasm:${MINSC_VERSION}

start:
	docker run --rm -p 8000:8000 libwally-wasm:${LIBWALLY_VERSION}

clean:
	docker rmi -f libwally-wasm:${LIBWALLY_VERSION}
	docker rmi -f libwally-wasm-test:${LIBWALLY_VERSION}

deep-clean:
	yes | docker system prune --all

.PHONY: build clean builder deep-clean test minsc bin
