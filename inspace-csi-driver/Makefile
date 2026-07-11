IMAGE_PLATFORM ?= linux/amd64

.PHONY: build fmt fmt-check image live-test smoke test verify

build:
	mkdir -p bin
	go build -trimpath -o bin/inspace-csi-driver ./cmd/inspace-csi-driver

image:
	docker build --platform=$(IMAGE_PLATFORM) -f Dockerfile -t inspace-csi-driver:dev ..

fmt:
	gofmt -w $$(find cmd pkg -name '*.go' -type f)

fmt-check:
	@test -z "$$(gofmt -l cmd pkg)" || (gofmt -l cmd pkg && exit 1)

smoke:
	go test ./pkg/driver -run '^TestCSIRWOLifecycleSmoke$$' -count=1 -v

live-test:
	@test "$$INSPACE_RUN_LIVE_TESTS" = true || (echo 'set INSPACE_RUN_LIVE_TESTS=true' >&2; exit 1)
	@test "$$INSPACE_ALLOW_REMOTE_MUTATIONS" = true || (echo 'set INSPACE_ALLOW_REMOTE_MUTATIONS=true' >&2; exit 1)
	go test -tags=live ./pkg/cloud/inspace -run '^TestLiveDiskLifecycle$$' -count=1 -v

test:
	go test ./...

verify: fmt-check test build
