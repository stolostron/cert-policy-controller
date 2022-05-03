# IBM Confidential
# OCO Source Materials
#
# (C) Copyright IBM Corporation 2018 All Rights Reserved
# The source code for this program is not published or otherwise divested of its trade secrets, irrespective of what has been deposited with the U.S. Copyright Office.
# Copyright (c) 2020 Red Hat, Inc.
# Copyright Contributors to the Open Cluster Management project


export PATH := $(PWD)/bin:$(PATH)
# Keep an existing GOPATH, make a private one if it is undefined
GOPATH_DEFAULT := $(PWD)/.go
export GOPATH ?= $(GOPATH_DEFAULT)
GOBIN_DEFAULT := $(GOPATH)/bin
export GOBIN ?= $(GOBIN_DEFAULT)
export PATH := $(PATH):$(GOBIN)
GOARCH = $(shell go env GOARCH)
GOOS = $(shell go env GOOS)
TESTARGS_DEFAULT := -v
TESTARGS ?= $(TESTARGS_DEFAULT)
# Deployment configuration
CONTROLLER_NAMESPACE ?= open-cluster-management-agent-addon
MANAGED_CLUSTER_NAME ?= managed
WATCH_NAMESPACE ?= $(MANAGED_CLUSTER_NAME)
# Handle KinD configuration
KIND_NAME ?= test-managed
KIND_VERSION ?= latest
ifneq ($(KIND_VERSION), latest)
	KIND_ARGS = --image kindest/node:$(KIND_VERSION)
else
	KIND_ARGS =
endif
# Fetch Ginkgo/Gomega versions from go.mod
GINKGO_VERSION := $(shell awk '/github.com\/onsi\/ginkgo\/v2/ {print $$2}' go.mod)
GOMEGA_VERSION := $(shell awk '/github.com\/onsi\/gomega/ {print $$2}' go.mod)
# Test coverage threshold
export COVERAGE_MIN ?= 65

# Image URL to use all building/pushing image targets;
# Use your own docker registry and image name for dev/test by overridding the IMG and REGISTRY environment variable.
IMG ?= $(shell cat COMPONENT_NAME 2> /dev/null)
REGISTRY ?= quay.io/stolostron
TAG ?= latest
IMAGE_NAME_AND_VERSION ?= $(REGISTRY)/$(IMG)

# go-get-tool will 'go get' any package $2 and install it to $1.
PROJECT_DIR := $(shell dirname $(abspath $(lastword $(MAKEFILE_LIST))))
define go-get-tool
@[ -f $(1) ] || { \
set -e ;\
TMP_DIR=$$(mktemp -d) ;\
cd $$TMP_DIR ;\
go mod init tmp ;\
echo "Downloading $(2)" ;\
GOBIN=$(PROJECT_DIR)/bin go get $(2) ;\
rm -rf $$TMP_DIR ;\
}
endef

include build/common/Makefile.common.mk

.PHONY: all test dependencies build image rhel-image run deploy install \
fmt vet generate go-coverage fmt-dependencies lint-dependencies

all: test

############################################################
# build, run
############################################################

dependencies-go:
	go mod tidy
	go mod download

build:
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -a -tags netgo -o ./build/_output/bin/cert-policy-controller ./main.go

# Run against the current locally configured Kubernetes cluster
run:
	WATCH_NAMESPACE=$(WATCH_NAMESPACE) go run ./main.go --leader-elect=false

############################################################
# deploy
############################################################

build-images:
	@docker build -t ${IMAGE_NAME_AND_VERSION} -f ./Dockerfile .
	@docker tag ${IMAGE_NAME_AND_VERSION} $(REGISTRY)/$(IMG):$(TAG)

# Install necessary resources into a cluster
deploy:
	kubectl apply -f deploy/operator.yaml -n $(CONTROLLER_NAMESPACE)
	kubectl apply -f deploy/crds/ -n $(CONTROLLER_NAMESPACE)
	kubectl set env deployment/$(IMG) -n $(CONTROLLER_NAMESPACE) WATCH_NAMESPACE=$(WATCH_NAMESPACE)

deploy-controller: create-ns install-crds
	@echo installing $(IMG)
	kubectl -n $(CONTROLLER_NAMESPACE) apply -f deploy/operator.yaml
	kubectl set env deployment/$(IMG) -n $(CONTROLLER_NAMESPACE) WATCH_NAMESPACE=$(WATCH_NAMESPACE)

create-ns:
	@kubectl create namespace $(CONTROLLER_NAMESPACE) || true
	@kubectl create namespace $(WATCH_NAMESPACE) || true

############################################################
# lint
############################################################

# Lint code
lint-dependencies:
	$(call go-get-tool,$(PWD)/bin/golangci-lint,github.com/golangci/golangci-lint/cmd/golangci-lint@v1.41.1)

lint: lint-dependencies lint-all

fmt-dependencies:
	$(call go-get-tool,$(PWD)/bin/gci,github.com/daixiang0/gci@v0.2.9)
	$(call go-get-tool,$(PWD)/bin/gofumpt,mvdan.cc/gofumpt@v0.2.0)

fmt: fmt-dependencies
	find . -not \( -path "./.go" -prune \) -name "*.go" | xargs gofmt -s -w
	find . -not \( -path "./.go" -prune \) -not \( -name "main.go" -prune \) -not \( -name "suite_test.go" -prune \) -name "*.go" | xargs gci -w -local "$(shell cat go.mod | head -1 | cut -d " " -f 2)"
	find . -not \( -path "./.go" -prune \) -name "*.go" | xargs gofumpt -l -w

# Run go vet against code
vet:
	go vet ./...

CONTROLLER_GEN = $(shell pwd)/bin/controller-gen
KUSTOMIZE = $(shell pwd)/bin/kustomize
CRD_OPTIONS ?= "crd:trivialVersions=true,preserveUnknownFields=false"

.PHONY: manifests
manifests: controller-gen kustomize
	$(CONTROLLER_GEN) $(CRD_OPTIONS) rbac:roleName=cert-policy-controller paths="./..." output:crd:artifacts:config=deploy/crds/kustomize output:rbac:artifacts:config=deploy/rbac
	$(KUSTOMIZE) build deploy/crds/kustomize > deploy/crds/policy.open-cluster-management.io_certificatepolicies.yaml

.PHONY: generate
generate: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

.PHONY: generate-operator-yaml
generate-operator-yaml: kustomize manifests
	$(KUSTOMIZE) build deploy/manager > deploy/operator.yaml

.PHONY: controller-gen
controller-gen: ## Download controller-gen locally if necessary.
	$(call go-get-tool,$(CONTROLLER_GEN),sigs.k8s.io/controller-tools/cmd/controller-gen@v0.6.1)

.PHONY: kustomize
kustomize: ## Download kustomize locally if necessary.
	$(call go-get-tool,$(KUSTOMIZE),sigs.k8s.io/kustomize/kustomize/v3@v3.8.7)

############################################################
# unit test
############################################################
GOSEC = $(shell pwd)/bin/gosec
GOSEC_VERSION = 2.9.6
KUBEBUILDER_DIR = /usr/local/kubebuilder/bin
KBVERSION = 3.2.0
K8S_VERSION = 1.21.2

test:
	go test $(TESTARGS) ./...

test-coverage: TESTARGS = -json -cover -covermode=atomic -coverprofile=coverage_unit.out
test-coverage: test

test-dependencies:
	@if (ls $(KUBEBUILDER_DIR)/*); then \
		echo "^^^ Files found in $(KUBEBUILDER_DIR). Skipping installation."; exit 1; \
	else \
		echo "^^^ Kubebuilder binaries not found. Installing Kubebuilder binaries."; \
	fi
	sudo mkdir -p $(KUBEBUILDER_DIR)
	sudo curl -L https://github.com/kubernetes-sigs/kubebuilder/releases/download/v$(KBVERSION)/kubebuilder_$(GOOS)_$(GOARCH) -o $(KUBEBUILDER_DIR)/kubebuilder
	sudo chmod +x $(KUBEBUILDER_DIR)/kubebuilder
	curl -L "https://go.kubebuilder.io/test-tools/$(K8S_VERSION)/$(GOOS)/$(GOARCH)" | sudo tar xz --strip-components=2 -C $(KUBEBUILDER_DIR)/

$(GOSEC):
	curl -L https://github.com/securego/gosec/releases/download/v$(GOSEC_VERSION)/gosec_$(GOSEC_VERSION)_$(GOOS)_$(GOARCH).tar.gz | tar -xz -C /tmp/
	sudo mv /tmp/gosec $(GOSEC)

gosec-scan: $(GOSEC)
	$(GOSEC) -fmt sonarqube -out gosec.json -no-fail -exclude-dir=.go ./...

############################################################
# e2e test (using KinD clusters)
############################################################

.PHONY: kind-bootstrap-cluster
kind-bootstrap-cluster: kind-create-cluster kind-deploy-controller install-resources

.PHONY: kind-bootstrap-cluster-dev
kind-bootstrap-cluster-dev: kind-create-cluster install-crds install-resources

kind-deploy-controller: install-crds
	@echo installing $(IMG)
	kubectl create ns $(CONTROLLER_NAMESPACE) || true
	kubectl apply -f deploy/operator.yaml -n $(CONTROLLER_NAMESPACE)
	kubectl patch deployment $(IMG) -n $(CONTROLLER_NAMESPACE) -p "{\"spec\":{\"template\":{\"spec\":{\"containers\":[{\"name\":\"$(IMG)\",\"env\":[{\"name\":\"WATCH_NAMESPACE\",\"value\":\"$(WATCH_NAMESPACE)\"}]}]}}}}"

kind-deploy-controller-dev: kind-deploy-controller
	@echo Pushing image to KinD cluster
	kind load docker-image $(REGISTRY)/$(IMG):$(TAG) --name $(KIND_NAME)
	@echo "Patch deployment image"
	kubectl patch deployment $(IMG) -n $(CONTROLLER_NAMESPACE) -p "{\"spec\":{\"template\":{\"spec\":{\"containers\":[{\"name\":\"$(IMG)\",\"imagePullPolicy\":\"Never\",\"args\":[]}]}}}}"
	kubectl patch deployment $(IMG) -n $(CONTROLLER_NAMESPACE) -p "{\"spec\":{\"template\":{\"spec\":{\"containers\":[{\"name\":\"$(IMG)\",\"image\":\"$(REGISTRY)/$(IMG):$(TAG)\"}]}}}}"
	kubectl rollout status -n $(CONTROLLER_NAMESPACE) deployment $(IMG) --timeout=180s

kind-create-cluster:
	@echo "creating cluster"
	kind create cluster --name $(KIND_NAME) $(KIND_ARGS)
	kind get kubeconfig --name $(KIND_NAME) > $(PWD)/kubeconfig_managed

kind-delete-cluster:
	kind delete cluster --name $(KIND_NAME)

install-crds:
	@echo installing crds
	kubectl apply -f deploy/crds/policy.open-cluster-management.io_certificatepolicies.yaml

install-resources:
	@echo creating namespaces
	kubectl create ns $(WATCH_NAMESPACE)

e2e-dependencies:
	go get github.com/onsi/ginkgo/v2/ginkgo@$(GINKGO_VERSION)
	go get github.com/onsi/gomega/...@$(GOMEGA_VERSION)

e2e-test:
	$(GOPATH)/bin/ginkgo -v --fail-fast --slow-spec-threshold=10s $(E2E_TEST_ARGS) test/e2e

e2e-test-coverage: E2E_TEST_ARGS = --json-report=report_e2e.json --output-dir=.
e2e-test-coverage: e2e-test

e2e-build-instrumented:
	go test -covermode=atomic -coverpkg=$(shell cat go.mod | head -1 | cut -d ' ' -f 2)/... -c -tags e2e ./ -o build/_output/bin/$(IMG)-instrumented

e2e-run-instrumented:
	WATCH_NAMESPACE="$(WATCH_NAMESPACE)" ./build/_output/bin/$(IMG)-instrumented -test.run "^TestRunMain$$" -test.coverprofile=coverage_e2e.out &>/dev/null &

e2e-stop-instrumented:
	ps -ef | grep '$(IMG)' | grep -v grep | awk '{print $$2}' | xargs kill

e2e-debug:
	kubectl get all -n $(CONTROLLER_NAMESPACE)
	kubectl get leases -n $(CONTROLLER_NAMESPACE)
	kubectl get all -n $(WATCH_NAMESPACE)
	kubectl get certificatepolicies.policy.open-cluster-management.io --all-namespaces
	kubectl describe pods -n $(CONTROLLER_NAMESPACE)
	kubectl logs $$(kubectl get pods -n $(CONTROLLER_NAMESPACE) -o name | grep $(IMG)) -n $(CONTROLLER_NAMESPACE)

############################################################
# test coverage
############################################################
GOCOVMERGE = $(shell pwd)/bin/gocovmerge
coverage-dependencies:
	$(call go-get-tool,$(GOCOVMERGE),github.com/wadey/gocovmerge)

COVERAGE_FILE = coverage.out
coverage-merge: coverage-dependencies
	@echo Merging the coverage reports into $(COVERAGE_FILE)
	$(GOCOVMERGE) $(PWD)/coverage_* > $(COVERAGE_FILE)

coverage-verify:
	./build/common/scripts/coverage_calc.sh
