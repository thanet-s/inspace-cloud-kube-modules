SHELL := /bin/sh

MODULES := modules/client modules/cloud-provider modules/csi-driver modules/karpenter-provider

.PHONY: all fmt test smoke vet helm-verify helm-package e2e-static release-notes-verify verify images status live-audit live-test cluster-e2e

all: test

fmt:
	@set -eu; for module in $(MODULES); do \
		echo "==> fmt $$module"; \
		(cd "$$module" && gofmt -w $$(find . -name '*.go' -not -path './vendor/*')); \
	done

test:
	@set -eu; for module in $(MODULES); do \
		echo "==> test $$module"; \
		(cd "$$module" && env \
			-u INSPACE_API_TOKEN \
			-u INSPACE_API_KEY \
			-u INSPACE_ALLOW_REMOTE_MUTATIONS \
			-u INSPACE_RUN_LIVE_TESTS \
			GOWORK=off \
			go test ./...); \
	done

smoke:
	@set -eu; for module in $(MODULES); do \
		echo "==> smoke $$module"; \
		(cd "$$module" && env \
			-u INSPACE_API_TOKEN \
			-u INSPACE_API_KEY \
			-u INSPACE_ALLOW_REMOTE_MUTATIONS \
			-u INSPACE_RUN_LIVE_TESTS \
			GOWORK=off \
			$(MAKE) smoke); \
	done

vet:
	@set -eu; for module in $(MODULES); do \
		echo "==> vet $$module"; \
		(cd "$$module" && GOWORK=off go vet ./...); \
	done

helm-verify:
	helm lint charts/inspace-cloud-kube-modules-crds
	helm lint charts/inspace-cloud-kube-modules --values charts/inspace-cloud-kube-modules/ci/test-values.yaml
	helm template verify-crds charts/inspace-cloud-kube-modules-crds >/dev/null
	helm template verify charts/inspace-cloud-kube-modules --namespace kube-system --values charts/inspace-cloud-kube-modules/ci/test-values.yaml >/dev/null
	./scripts/verify-bootstrap-manifests.sh

helm-package: helm-verify
	rm -rf dist
	mkdir -p dist
	helm package charts/inspace-cloud-kube-modules-crds --destination dist
	helm package charts/inspace-cloud-kube-modules --destination dist

e2e-static:
	python3 test/e2e/verify-static.py
	@set -eu; for script in test/e2e/run.sh test/e2e/scripts/*.sh; do \
		bash -n "$$script"; \
	done

release-notes-verify:
	@./scripts/test-filter-release-notes.sh

verify: test smoke vet helm-verify e2e-static release-notes-verify

images:
	docker build --platform=linux/amd64 -f modules/cloud-provider/Dockerfile -t inspace-cloud-controller-manager:dev .
	docker build --platform=linux/amd64 -f modules/csi-driver/Dockerfile -t inspace-csi-driver:dev .
	docker build --platform=linux/amd64 -f modules/karpenter-provider/Dockerfile -t karpenter-provider-inspace:dev .

status:
	@git status --short --branch

live-audit:
	@./scripts/live-audit.sh

live-test:
	@MAKE="$(MAKE)" ./scripts/live-suite.sh

cluster-e2e:
	@./test/e2e/run.sh
