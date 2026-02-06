VERSION?=0.0.1
REPO?=docker.io
IMAGE_PATH?=stevegargan/cert-scanner-darkly
IMAGE=${REPO}/${IMAGE_PATH}:${VERSION}

GIT_COMMIT     = $(shell git rev-parse HEAD | cut -b 1-8)
BUILD_TIME    ?= $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')

GOLDFLAGS += -X github.com/sgargan/cert-scanner-darkly/version.Buildtime=$(BUILD_TIME)
GOLDFLAGS += -X github.com/sgargan/cert-scanner-darkly/version.Commit=$(GIT_COMMIT)
GOLDFLAGS += -X github.com/sgargan/cert-scanner-darkly/version.Version=$(VERSION)
GOLDFLAGS += -s -w
GOFLAGS = -ldflags "$(GOLDFLAGS)"
GOOS = $(shell go version | awk '{split($$4, a, "/"); print a[1]}')

CHART = cert-scanner

IMAGE_ARGS += --build-arg BUILD_NUMBER=$(BUILD_NUMBER)
IMAGE_ARGS += --build-arg GIT_COMMIT=$(GIT_COMMIT)
IMAGE_ARGS := --build-arg VERSION=$(VERSION)
IMAGE_ARGS += --label "com.qualtrics.build-info.git-commit=$(GIT_COMMIT)"
IMAGE_ARGS += --label "com.qualtrics.build-info.build-time=$(BUILD_TIME)"

NAMESPACE ?= security-scanners

KO_DOCKER_REPO ?= docker.io/stevegargan

.PHONY: local-dev deploy-local
.PHONY: deploy-remote

bootstrap:
	./scripts/bootstrap.sh

local-dev: VERSION=dev
local-dev: KO_DOCKER_REPO=ko.local
local-dev:
	ko build github.com/sgargan/cert-scanner-darkly --tags $(VERSION) --base-import-paths -L
	$(eval IMAGE:=$(KO_DOCKER_REPO)/cert-scanner-darkly:$(VERSION))
	kind load docker-image --name cert-scanner $(IMAGE)
	$(call deploy)

local-canary: VERSION=dev
local-canary: KO_DOCKER_REPO=ko.local
local-canary: CHART=cert-scanner-canary
local-canary:
	$(call deploy)

deps:
	cd cert-scanner && go mod download

build:
	cd cert-scanner && go build -o build/cert-scanner -ldflags "$(GOLDFLAGS)" main.go

install-mockery:
	@{ [ -x ${GOPATH}/bin/mockery ] || go install github.com/vektra/mockery/v2@v2.35.2; }

generate: install-mockery
	cd cert-scanner && go generate ./...

install-tparse:
	@{ [ -x ${GOPATH}/bin/tparse ] || go install github.com/mfridman/tparse@latest ;}

test: install-tparse
	cd cert-scanner && go test ./... -json -v -p 1 -count=1 -coverprofile=coverage.out | tparse -follow -all

cover: test
	go tool cover -html=coverage.out

build-image:
	KO_DOCKER_REPO=$(KO_DOCKER_REPO) ko build github.com/sgargan/cert-scanner-darkly --tags $(VERSION) --base-import-paths

deploy:
	$(call deploy)

define deploy
	$(eval URL:=$(KO_DOCKER_REPO)/cert-scanner-darkly)
	{ kubectl create namespace ${NAMESPACE} || true ;}
	helm upgrade --install -n ${NAMESPACE} $(CHART) charts/$(CHART) --values charts/cert-scanner/values.yaml --set image.url=$(URL) --set image.tag=$(VERSION) --set image.pullPolicy=Never
	kubectl rollout restart deployment -n ${NAMESPACE} $(CHART)
endef
