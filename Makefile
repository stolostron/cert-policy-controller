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
TAG ?= latest
KIND_VERSION ?= latest
ifneq $(KIND_VERSION), 'latest'
	KIND_ARGS = '--image kindest/node:$(KIND_VERSION)'
else
	KIND_ARGS = ''
endif

# Image URL to use all building/pushing image targets;
# Use your own docker registry and image name for dev/test by overridding the IMG and REGISTRY environment variable.
IMG ?= $(shell cat COMPONENT_NAME 2> /dev/null)
REGISTRY ?= quay.io/open-cluster-management
TAG ?= latest

ifndef USE_VENDORIZED_BUILD_HARNESS
-include $(shell curl -s -H 'Accept: application/vnd.github.v4.raw' -L https://api.github.com/repos/open-cluster-management/build-harness-extensions/contents/templates/Makefile.build-harness-bootstrap -o .build-harness-bootstrap; echo .build-harness-bootstrap)
else
-include vbh/.build-harness-bootstrap
endif

.PHONY: default
default::
	@echo "Build Harness Bootstrapped"

.PHONY: all test dependencies build image rhel-image manager run deploy install \
fmt vet generate go-coverage

all: test manager

dependencies: dependencies-go
	curl -sL https://go.kubebuilder.io/dl/2.0.0-alpha.1/${GOOS}/${GOARCH} | tar -xz -C /tmp/
	sudo mv /tmp/kubebuilder_2.0.0-alpha.1_${GOOS}_${GOARCH} /usr/local/kubebuilder

dependencies-go:
	go mod tidy
	go mod download

build:
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -a -tags netgo -o ./build/_output/bin/cert-policy-controller ./cmd/manager

# Run against the configured Kubernetes cluster in ~/.kube/config
run: generate fmt vet
	go run ./cmd/manager/main.go

# Install CRDs into a cluster
install: manifests
	kubectl apply -f config/crds

# Deploy controller in the configured Kubernetes cluster in ~/.kube/config
deploy: manifests
	kubectl apply -f config/crds
	kustomize build config/default | kubectl apply -f -

# Generate manifests e.g. CRD, RBAC etc.
manifests:
	go run vendor/sigs.k8s.io/controller-tools/cmd/controller-gen/main.go all

# Run go fmt against code
fmt:
	go fmt ./pkg/... ./cmd/...

# Run go vet against code
vet:
	go vet ./pkg/... ./cmd/...

test:
	go test ./...

# Generate code
generate:
	go generate ./pkg/... ./cmd/...

copyright-check:
	./build/copyright-check.sh $(TRAVIS_BRANCH) $(TRAVIS_PULL_REQUEST_BRANCH)

# e2e test section
.PHONY: kind-bootstrap-cluster
kind-bootstrap-cluster: kind-create-cluster install-crds kind-deploy-controller install-resources

.PHONY: kind-bootstrap-cluster-dev
kind-bootstrap-cluster-dev: kind-create-cluster install-crds install-resources

check-env:
ifndef DOCKER_USER
	$(error DOCKER_USER is undefined)
endif
ifndef DOCKER_PASS
	$(error DOCKER_PASS is undefined)
endif

kind-deploy-controller: check-env
	@echo installing cert policy controller
	kubectl create ns multicluster-endpoint
	kubectl create secret -n multicluster-endpoint docker-registry multiclusterhub-operator-pull-secret --docker-server=quay.io --docker-username=${DOCKER_USER} --docker-password=${DOCKER_PASS}
	kubectl apply -f deploy/ -n multicluster-endpoint

kind-deploy-controller-dev:
	@echo Pushing image to KinD cluster
	kind load docker-image $(REGISTRY)/$(IMG):$(TAG) --name test-managed
	@echo Installing cert policy controller
	kubectl create ns multicluster-endpoint
	kubectl apply -f deploy/ -n multicluster-endpoint
	@echo "Patch deployment image"
	kubectl patch deployment cert-policy-ctrl -n multicluster-endpoint -p "{\"spec\":{\"template\":{\"spec\":{\"containers\":[{\"name\":\"cert-policy-ctrl\",\"imagePullPolicy\":\"Never\"}]}}}}"
	kubectl patch deployment cert-policy-ctrl -n multicluster-endpoint -p "{\"spec\":{\"template\":{\"spec\":{\"containers\":[{\"name\":\"cert-policy-ctrl\",\"image\":\"$(REGISTRY)/$(IMG):$(TAG)\"}]}}}}"
	kubectl rollout status -n multicluster-endpoint deployment cert-policy-ctrl --timeout=180s

kind-create-cluster:
	@echo "creating cluster"
	kind create cluster --name test-managed $(KIND_ARGS)
	kind get kubeconfig --name test-managed > $(PWD)/kubeconfig_managed

kind-delete-cluster:
	kind delete cluster --name test-managed

install-crds:
	@echo installing crds
	kubectl apply -f deploy/crds/policy.open-cluster-management.io_certificatepolicies_crd.yaml

install-resources:
	@echo creating namespaces
	kubectl create ns managed

e2e-test:
	${GOPATH}/bin/ginkgo -v --failFast --slowSpecThreshold=10 test/e2e
