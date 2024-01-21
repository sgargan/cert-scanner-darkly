VERSION=0.0.2
REPO= docker.io
IMAGE_PATH=stevegargan/cert-scanner-darkly
IMAGE=${REPO}/${IMAGE_PATH}:${VERSION}

GIT_COMMIT     = $(shell git rev-parse HEAD | cut -b 1-8)
BUILD_TIME    ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')

GOLDFLAGS += -X github.com/sgargan/cert-scanner-darkly/version.Buildtime=$(BUILD_TIME)
GOLDFLAGS += -X github.com/sgargan/cert-scanner-darkly/version.Commit=$(GIT_COMMIT)
GOLDFLAGS += -X github.com/sgargan/cert-scanner-darkly/version.Version=$(VERSION)
GOLDFLAGS += -s -w
GOFLAGS = -ldflags "$(GOLDFLAGS)"
GOOS = $(shell go version | awk '{split($$4, a, "/"); print a[1]}')

IMAGE_ARGS += --build-arg BUILD_NUMBER=$(BUILD_NUMBER)
IMAGE_ARGS += --build-arg GIT_COMMIT=$(GIT_COMMIT)
IMAGE_ARGS := --build-arg VERSION=$(VERSION)
IMAGE_ARGS += --label "com.qualtrics.build-info.git-commit=$(GIT_COMMIT)"
IMAGE_ARGS += --label "com.qualtrics.build-info.build-time=$(BUILD_TIME)"

NAMESPACE ?= security-scanners

deps:
	cd cert-scanner && go mod download

build: 
	cd cert-scanner && go build -o build/cert-scanner -ldflags "$(GOLDFLAGS)" main/main.go

install-mockery:
	@{ [ -x ${GOPATH}/bin/mockery ] || go install github.com/vektra/mockery/v2@v2.35.2; }

generate: install-mockery
	go generate ./... 

install-tparse:
	@{ [ -x ${GOPATH}/bin/tparse ] || go install github.com/mfridman/tparse@latest ;}

test: install-tparse
	cd cert-scanner && go test ./... -json -v -p 1 -count=1  | tparse -follow -all

cover: test
	go tool cover -html=coverage.out

build-image:
	docker buildx build --platform linux/amd64,linux/arm64 --push -t ${IMAGE} -f docker/Dockerfile .

build-local:
	docker build -t ${IMAGE} --load -f docker/Dockerfile .
	kind load docker-image ${IMAGE} --name cert-scanner

publish:
	docker push ${IMAGE}

deploy:
	{ kubectl create namespace ${NAMESPACE} || true ;}
	helm upgrade --install -n ${NAMESPACE} cert-scanner helm --values helm/values.yaml
	kubectl rollout restart deployment -n ${NAMESPACE}  cert-scanner

.PHONY: build build-image
