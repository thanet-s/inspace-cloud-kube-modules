IMAGE_PLATFORM ?= linux/amd64
GOWORK ?= off

.PHONY: build fmt fmt-check image live-test smoke test verify

build:
	mkdir -p bin
	GOWORK=$(GOWORK) go build -trimpath -o bin/inspace-csi-driver ./cmd/inspace-csi-driver

image:
	docker build --platform=$(IMAGE_PLATFORM) -f Dockerfile -t inspace-csi-driver:dev ../..

fmt:
	gofmt -w $$(find cmd pkg -name '*.go' -type f)

fmt-check:
	@test -z "$$(gofmt -l cmd pkg)" || (gofmt -l cmd pkg && exit 1)

smoke:
	GOWORK=$(GOWORK) go test ./pkg/driver -run '^TestCSIRWOLifecycleSmoke$$' -count=1 -v

live-test:
	@echo 'retired: unjournaled module live tests are unsafe; use root make live-test or make cluster-e2e' >&2
	@exit 1

test:
	GOWORK=$(GOWORK) go test ./...

verify: fmt-check test build
