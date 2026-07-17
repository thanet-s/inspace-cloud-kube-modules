.PHONY: all build image fmt test smoke vet live-read live-test clean

GOWORK ?= off
IMAGE_PLATFORM ?= linux/amd64

all: fmt test build

fmt:
	GOWORK=$(GOWORK) gofmt -w $$(find . -name '*.go' -not -path './.git/*')

test:
	GOWORK=$(GOWORK) go test ./...

smoke:
	GOWORK=$(GOWORK) go test ./pkg/bootstrap -run '^(TestReconcileBuildsBastionThenExactlyThreeControlPlaneVMs|TestReconcileSequencesControlPlaneCreatesAfterPriorFirewallReadback)$$' -count=1 -v
	GOWORK=$(GOWORK) go test ./pkg/cloudprovider -run '^(TestPublicLoadBalancerUsesExplicitOwnedFloatingIP|TestNodeLoadBalancerReconcileSmokeCreatesOwnedKarpenterAndDatapathResources)$$' -count=1 -v

vet:
	GOWORK=$(GOWORK) go vet ./...

live-read:
	@test -n "$$INSPACE_API_TOKEN" -o -n "$$INSPACE_API_KEY" || (echo "INSPACE_API_TOKEN is required" >&2; exit 1)
	GOWORK=$(GOWORK) go run ./cmd/inspace-discovery --location "$${INSPACE_LOCATION:-bkk01}" --smoke

live-test:
	@echo "retired: unjournaled module live tests are unsafe; use root make live-test or make cluster-e2e" >&2
	@exit 1

build:
	mkdir -p bin
	GOWORK=$(GOWORK) go build -o bin/inspace-cluster-controller ./cmd/inspace-cluster-controller
	GOWORK=$(GOWORK) go build -o bin/inspace-cloud-controller-manager ./cmd/inspace-cloud-controller-manager
	GOWORK=$(GOWORK) go build -o bin/inspace-discovery ./cmd/inspace-discovery

image:
	docker build --platform=$(IMAGE_PLATFORM) -f Dockerfile -t "$${INSPACE_CCM_IMAGE:-ghcr.io/thanet-s/inspace-cloud-controller-manager:dev}" ../..

clean:
	rm -rf bin coverage.out
