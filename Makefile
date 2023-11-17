VERSION=0.0.1
REPO= docker.io
IMAGE_PATH=/sgargan/cert-scanner-darkly
IMAGE=${REPO}${IMAGE_PATH}:${VERSION}

GIT_COMMIT     = $(shell git rev-parse HEAD | cut -b 1-8)
BUILD_TIME    ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')

GOLDFLAGS += -X github.com/sgargan/cert-scanner-darkly/version.Buildtime=$(BUILD_TIME)
GOLDFLAGS += -X github.com/sgargan/cert-scanner-darkly/version.Commit=$(GIT_COMMIT)
GOLDFLAGS += -X github.com/sgargan/cert-scanner-darkly/version.Version=$(VERSION)
GOFLAGS = -ldflags "$(GOLDFLAGS)"
GOOS = $(shell go version | awk '{split($$4, a, "/"); print a[1]}')

IMAGE_ARGS += --build-arg BUILD_NUMBER=$(BUILD_NUMBER)
IMAGE_ARGS += --build-arg GIT_COMMIT=$(GIT_COMMIT)
IMAGE_ARGS := --build-arg VERSION=$(VERSION)
IMAGE_ARGS += --label "com.qualtrics.build-info.git-commit=$(GIT_COMMIT)"
IMAGE_ARGS += --label "com.qualtrics.build-info.build-time=$(BUILD_TIME)"

install-mockery:
	@{ [ -x ${GOPATH}/bin/mockery ] || go install github.com/vektra/mockery/v2@v2.35.2; }

generate: install-mockery
	go generate ./... 

install-tparse:
	@{ [ -x ${GOPATH}/bin/tparse ] || go install github.com/mfridman/tparse@latest ;}

test: install-tparse
	go test ./... -json -v -p 1 -count=1 -coverprofile=coverage.out  | tparse -follow -all

cover: test
	go tool cover -html=coverage.out

build: 
	go build -o build/cert-scanner -ldflags "$(GOLDFLAGS)" main/main.go

build-image:
	DOCKER_BUILDKIT=0 docker build -t ${IMAGE} -f docker/Dockerfile

.PHONY: build build-image
