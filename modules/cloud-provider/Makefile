.PHONY: all build image fmt test smoke vet live-read live-test clean

GOWORK ?= off
IMAGE_PLATFORM ?= linux/amd64

all: fmt test build

fmt:
	GOWORK=$(GOWORK) gofmt -w $$(find . -name '*.go' -not -path './.git/*')

test:
	GOWORK=$(GOWORK) go test ./...

smoke:
	GOWORK=$(GOWORK) go test ./pkg/bootstrap -run '^(TestReconcileBuildsBastionThenExactlyThreeControlPlaneVMs|TestReconcileStartsAllThreeControlPlaneCreatesBehindOneBarrier)$$' -count=1 -v
	GOWORK=$(GOWORK) go test ./pkg/cloudprovider -run '^(TestPublicLoadBalancerUsesExplicitOwnedFloatingIP|TestNodeLoadBalancerReconcileSmokeCreatesOwnedKarpenterAndShadowResources)$$' -count=1 -v

vet:
	GOWORK=$(GOWORK) go vet ./...

live-read:
	@test -n "$$INSPACE_API_TOKEN" -o -n "$$INSPACE_API_KEY" || (echo "INSPACE_API_TOKEN is required" >&2; exit 1)
	GOWORK=$(GOWORK) go run ./cmd/inspace-discovery --location "$${INSPACE_LOCATION:-bkk01}" --smoke

live-test:
	@test "$$INSPACE_RUN_LIVE_TESTS" = "true" || (echo "INSPACE_RUN_LIVE_TESTS=true is required" >&2; exit 1)
	@test "$$INSPACE_ALLOW_REMOTE_MUTATIONS" = "true" || (echo "INSPACE_ALLOW_REMOTE_MUTATIONS=true is required" >&2; exit 1)
	GOWORK=$(GOWORK) go test -tags=live ./integration -run '^TestLiveLifecycle$$' -count=1 -v -timeout=30m

build:
	mkdir -p bin
	GOWORK=$(GOWORK) go build -o bin/inspace-cluster-controller ./cmd/inspace-cluster-controller
	GOWORK=$(GOWORK) go build -o bin/inspace-cloud-controller-manager ./cmd/inspace-cloud-controller-manager
	GOWORK=$(GOWORK) go build -o bin/inspace-discovery ./cmd/inspace-discovery

image:
	docker build --platform=$(IMAGE_PLATFORM) -f Dockerfile -t "$${INSPACE_CCM_IMAGE:-ghcr.io/thanet-s/inspace-cloud-controller-manager:dev}" ../..

clean:
	rm -rf bin coverage.out
