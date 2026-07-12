.PHONY: all fmt test smoke vet verify

GOWORK ?= off

all: verify

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './vendor/*')

test:
	GOWORK=$(GOWORK) go test ./...

smoke:
	GOWORK=$(GOWORK) go test . -run '^TestSmoke$$' -count=1 -v

vet:
	GOWORK=$(GOWORK) go vet ./...

verify: test vet
