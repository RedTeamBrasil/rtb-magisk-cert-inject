# Makefile — atalhos locais.
#
#   make build              compila e empacota em dist/
#   make test               build + self-test (openssl) + go vet
#   make clean              remove bin/ e dist/
#   make release TAG=v1.2   cria a tag e empurra (dispara o GitHub Release)
#
# O release exige que module.prop já esteja com version=v1.2 e versionCode
# incrementado; o workflow falha se a tag não bater com o version=.

SHELL := /bin/sh
VERSION := $(shell sed -n 's/^version=//p' module.prop)

.PHONY: build test clean release

build:
	./build.sh

test:
	./build.sh
	go vet ./src

clean:
	rm -rf bin dist

release:
	@test -n "$(TAG)" || { echo "uso: make release TAG=v1.2"; exit 1; }
	@test "$(TAG)" = "$(VERSION)" || { echo "TAG ($(TAG)) != module.prop version ($(VERSION))"; exit 1; }
	@test -z "$$(git status --porcelain)" || { echo "há mudanças não commitadas; commite antes de taguear"; exit 1; }
	@! git rev-parse -q --verify "refs/tags/$(TAG)" >/dev/null || { echo "tag $(TAG) já existe"; exit 1; }
	git tag -a "$(TAG)" -m "Cert Inject $(TAG)"
	git push origin "$(TAG)"
