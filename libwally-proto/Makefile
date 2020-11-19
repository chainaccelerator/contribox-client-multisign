.DEFAULT_GOAL := build
LIBWALLY_VERSION?=0.8.0
PROTO_VERSION?=0.1.0
#ELEMENTS_VERSION?=0.18.1.8

builder:
	docker build -f docker/ubuntu/libwally-core-builder.dockerfile --build-arg=LIBWALLY_CORE_VERSION=$(LIBWALLY_VERSION) . -t libwally-core-builder:$(LIBWALLY_VERSION)-ubuntu

libwally-core: builder
	docker build -f docker/ubuntu/libwally-core.dockerfile --build-arg=LIBWALLY_CORE_VERSION=$(LIBWALLY_VERSION) . -t libwally-core:$(LIBWALLY_VERSION)-ubuntu

wallycore: builder
	docker build -f docker/ubuntu/wallycore.dockerfile --build-arg=LIBWALLY_CORE_VERSION=$(LIBWALLY_VERSION) . -t wallycore:$(LIBWALLY_VERSION)-ubuntu

contribox-proto-server: wallycore
	docker build -f docker/ubuntu/contribox_proto-server.dockerfile --build-arg=LIBWALLY_CORE_VERSION=$(LIBWALLY_VERSION) . -t contribox_proto-server:$(LIBWALLY_VERSION)-ubuntu
	docker volume create contribox_proto-keys

server: contribox-proto-server
	docker run -ti --rm --mount source=contribox_proto-keys,target=/contribox_proto-keys -p 5500:5000 contribox_proto-server:$(LIBWALLY_VERSION)-ubuntu python3 /contribox_proto/server/server.py

build: libwally-core wallycore contribox-proto-server

clean:
	docker rmi -f wallycore:$(LIBWALLY_VERSION)-ubuntu libwally-core:$(LIBWALLY_VERSION)-ubuntu libwally-core-builder:$(LIBWALLY_VERSION)-ubuntu

deep-clean:
	yes | docker system prune --all

.PHONY: build clean start builder libwally-core wallycore contribox-proto contribox-proto-server server
