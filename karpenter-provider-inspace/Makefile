.PHONY: all fmt test smoke live-test vet verify image

GOWORK ?= auto
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
	@test "$$INSPACE_RUN_LIVE_TESTS" = "true" || (echo "refusing: set INSPACE_RUN_LIVE_TESTS=true"; exit 1)
	@test "$$INSPACE_ALLOW_REMOTE_MUTATIONS" = "true" || (echo "refusing: set INSPACE_ALLOW_REMOTE_MUTATIONS=true"; exit 1)
	GOWORK=$(GOWORK) go test -v -timeout 30m ./test/live -run '^TestLiveAdapterCreateGetListDelete$$'

vet:
	GOWORK=$(GOWORK) go vet ./...

verify: test vet

image:
	docker build --platform=$(PLATFORM) --file Dockerfile --tag $(IMAGE) ..
