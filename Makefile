# IBM Confidential
# OCO Source Materials
#
# (C) Copyright IBM Corporation 2018 All Rights Reserved
# The source code for this program is not published or otherwise divested of its trade secrets, irrespective of what has been deposited with the U.S. Copyright Office.
# Copyright (c) 2020 Red Hat, Inc.
# Copyright Contributors to the Open Cluster Management project


USE_VENDORIZED_BUILD_HARNESS ?=
GOARCH = $(shell go env GOARCH)
GOOS = $(shell go env GOOS)
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
# KubeBuilder configuration
KBVERSION := 2.3.1

# Image URL to use all building/pushing image targets;
# Use your own docker registry and image name for dev/test by overridding the IMG and REGISTRY environment variable.
IMG ?= $(shell cat COMPONENT_NAME 2> /dev/null)
REGISTRY ?= quay.io/stolostron
TAG ?= latest
IMAGE_NAME_AND_VERSION ?= $(REGISTRY)/$(IMG)

ifndef USE_VENDORIZED_BUILD_HARNESS
-include $(shell curl -s -H 'Accept: application/vnd.github.v4.raw' -L https://api.github.com/repos/stolostron/build-harness-extensions/contents/templates/Makefile.build-harness-bootstrap -o .build-harness-bootstrap; echo .build-harness-bootstrap)
else
-include vbh/.build-harness-bootstrap
endif

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

.PHONY: default
default::
	@echo "Build Harness Bootstrapped"

.PHONY: all test dependencies build image rhel-image manager run deploy install \
fmt vet generate go-coverage

all: test manager

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
	go run ./main.go --leader-elect=false

############################################################
# deploy
############################################################

build-images:
	@docker build -t ${IMAGE_NAME_AND_VERSION} -f ./Dockerfile .
	@docker tag ${IMAGE_NAME_AND_VERSION} $(REGISTRY)/$(IMG):$(TAG)

# Install necessary resources into a cluster
deploy:
	kubectl apply -f deploy/ -n $(CONTROLLER_NAMESPACE)
	kubectl apply -f deploy/crds/ -n $(CONTROLLER_NAMESPACE)
	kubectl set env deployment/$(IMG) -n $(CONTROLLER_NAMESPACE) WATCH_NAMESPACE=$(WATCH_NAMESPACE)

deploy-controller: create-ns install-crds
	@echo installing $(IMG)
	kubectl -n $(CONTROLLER_NAMESPACE) apply -f deploy/
	kubectl set env deployment/$(IMG) -n $(CONTROLLER_NAMESPACE) WATCH_NAMESPACE=$(WATCH_NAMESPACE)

create-ns:
	@kubectl create namespace $(CONTROLLER_NAMESPACE) || true
	@kubectl create namespace $(WATCH_NAMESPACE) || true

############################################################
# lint
############################################################

# Lint code
lint:
	go fmt ./ ./pkg/... ./apis/...

# Run go vet against code
vet:
	go vet ./ ./pkg/... ./apis/...

CONTROLLER_GEN = $(shell pwd)/bin/controller-gen
controller-gen: ## Download controller-gen locally if necessary.
	$(call go-get-tool,$(CONTROLLER_GEN),sigs.k8s.io/controller-tools/cmd/controller-gen@v0.6.1)

# Generate code
generate: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

copyright-check:
	./build/copyright-check.sh $(TRAVIS_BRANCH) $(TRAVIS_PULL_REQUEST_BRANCH)

############################################################
# unit test
############################################################

test:
	go test ./...

test-dependencies:
	curl -L https://github.com/kubernetes-sigs/kubebuilder/releases/download/v$(KBVERSION)/kubebuilder_$(KBVERSION)_$(GOOS)_$(GOARCH).tar.gz | tar -xz -C /tmp/
	sudo mv /tmp/kubebuilder_$(KBVERSION)_$(GOOS)_$(GOARCH) /usr/local/kubebuilder

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
	kubectl apply -f deploy/ -n $(CONTROLLER_NAMESPACE)
	kubectl patch deployment $(IMG) -n $(CONTROLLER_NAMESPACE) -p "{\"spec\":{\"template\":{\"spec\":{\"containers\":[{\"name\":\"$(IMG)\",\"env\":[{\"name\":\"WATCH_NAMESPACE\",\"value\":\"$(WATCH_NAMESPACE)\"}]}]}}}}"

kind-deploy-controller-dev:
	@echo Pushing image to KinD cluster
	kind load docker-image $(REGISTRY)/$(IMG):$(TAG) --name $(KIND_NAME)
	@echo Installing $(IMG)
	kubectl create ns $(CONTROLLER_NAMESPACE)
	kubectl apply -f deploy/ -n $(CONTROLLER_NAMESPACE)
	@echo "Patch deployment image"
	kubectl patch deployment $(IMG) -n $(CONTROLLER_NAMESPACE) -p "{\"spec\":{\"template\":{\"spec\":{\"containers\":[{\"name\":\"$(IMG)\",\"imagePullPolicy\":\"Never\"}]}}}}"
	kubectl patch deployment $(IMG) -n $(CONTROLLER_NAMESPACE) -p "{\"spec\":{\"template\":{\"spec\":{\"containers\":[{\"name\":\"$(IMG)\",\"image\":\"$(REGISTRY)/$(IMG):$(TAG)\"}]}}}}"
	kubectl patch deployment $(IMG) -n $(CONTROLLER_NAMESPACE) -p "{\"spec\":{\"template\":{\"spec\":{\"containers\":[{\"name\":\"$(IMG)\",\"env\":[{\"name\":\"WATCH_NAMESPACE\",\"value\":\"$(WATCH_NAMESPACE)\"}]}]}}}}"
	kubectl rollout status -n $(CONTROLLER_NAMESPACE) deployment $(IMG) --timeout=180s

kind-create-cluster:
	@echo "creating cluster"
	kind create cluster --name $(KIND_NAME) $(KIND_ARGS)
	kind get kubeconfig --name $(KIND_NAME) > $(PWD)/kubeconfig_managed

kind-delete-cluster:
	kind delete cluster --name $(KIND_NAME)

install-crds:
	@echo installing crds
	kubectl apply -f deploy/crds/v1/policy.open-cluster-management.io_certificatepolicies.yaml

install-resources:
	@echo creating namespaces
	kubectl create ns $(WATCH_NAMESPACE)

e2e-test:
	${GOPATH}/bin/ginkgo -v --failFast --slowSpecThreshold=10 test/e2e

e2e-dependencies:
	go get github.com/onsi/ginkgo/ginkgo
	go get github.com/onsi/gomega/...

e2e-debug:
	kubectl get all -n $(CONTROLLER_NAMESPACE)
	kubectl get leases -n $(CONTROLLER_NAMESPACE)
	kubectl get all -n $(WATCH_NAMESPACE)
	kubectl get certificatepolicies.policy.open-cluster-management.io --all-namespaces
	kubectl describe pods -n $(CONTROLLER_NAMESPACE)
	kubectl logs $$(kubectl get pods -n $(CONTROLLER_NAMESPACE) -o name | grep $(IMG)) -n $(CONTROLLER_NAMESPACE)
