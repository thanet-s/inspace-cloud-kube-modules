.PHONY: all fmt test smoke live-test vet verify image

GOWORK ?= off
IMAGE ?= ghcr.io/thanet-s/karpenter-provider-inspace:dev
PLATFORM ?= linux/amd64

all: verify

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*')

test:
	GOWORK=$(GOWORK) go test ./...

smoke:
	GOWORK=$(GOWORK) go test -v ./test/smoke

live-test:
	@echo "retired: unjournaled module live tests are unsafe; use root make live-test or make cluster-e2e" >&2
	@exit 1

vet:
	GOWORK=$(GOWORK) go vet ./...

verify: test vet

image:
	docker build --platform=$(PLATFORM) --file Dockerfile --tag $(IMAGE) ../..
