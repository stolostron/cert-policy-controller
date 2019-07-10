include Configfile
# Copyright 2019 The Jetstack cert-manager contributors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# CICD BUILD HARNESS
####################
GITHUB_USER := $(shell echo $(GITHUB_USER) | sed 's/@/%40/g')

.PHONY: default
default:: init;

.PHONY: init\:
init::
	@mkdir -p variables
ifndef GITHUB_USER
	$(info GITHUB_USER not defined)
	exit -1
endif
	$(info Using GITHUB_USER=$(GITHUB_USER))
ifndef GITHUB_TOKEN
	$(info GITHUB_TOKEN not defined)
	exit -1
endif

-include $(shell curl -fso .build-harness -H "Authorization: token ${GITHUB_TOKEN}" -H "Accept: application/vnd.github.v3.raw" "https://raw.github.ibm.com/ICP-DevOps/build-harness/master/templates/Makefile.build-harness"; echo .build-harness)

.PHONY: all lint test build image rhel-image manager run deploy install \
fmt vet generate docker-push docker-push-rhel

all: test manager

lint:
	@echo "Linting disabled."

# Run tests
test: generate fmt vet manifests
	curl -sL https://go.kubebuilder.io/dl/2.0.0-alpha.1/${GOOS}/${GOARCH} | tar -xz -C /tmp/

	sudo mv /tmp/kubebuilder_2.0.0-alpha.1_${GOOS}_${GOARCH} /usr/local/kubebuilder
	go test ./pkg/... ./cmd/... -v -coverprofile cover.out

build:
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -a -tags netgo -o ./cert-policy_$(GOARCH) ./cmd/manager

image:
	$(eval DOCKER_BUILD_OPTS := '--build-arg "VCS_REF=$(GIT_COMMIT)" \
		--build-arg "VCS_URL=$(GIT_REMOTE_URL)" \
		--build-arg "IMAGE_NAME=$(DOCKER_IMAGE)" \
		--build-arg "IMAGE_DESCRIPTION=$(IMAGE_DESCRIPTION)" \
		--build-arg "SUMMARY=$(SUMMARY)" \
		--build-arg "GOARCH=$(GOARCH)"')
	@make DOCKER_BUILD_OPTS=$(DOCKER_BUILD_OPTS) docker:build
	@make docker:tag

rhel-image:
	docker tag $(DOCKER_REGISTRY)/$(DOCKER_NAMESPACE)/$(DOCKER_IMAGE):$(DOCKER_BUILD_TAG) $(DOCKER_REGISTRY)/$(DOCKER_NAMESPACE)/$(DOCKER_IMAGE):$(DOCKER_BUILD_TAG_RHEL)

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

# Generate code
generate:
	go generate ./pkg/... ./cmd/...

# Push the docker image
docker-push:
	@make docker:push
ifneq ($(RETAG),)
	$(eval RELEASE := $(DOCKER_REGISTRY)/$(DOCKER_NAMESPACE)/$(DOCKER_IMAGE):$(RELEASE_TAG))
	docker tag $(DOCKER_REGISTRY)/$(DOCKER_NAMESPACE)/$(DOCKER_IMAGE):$(DOCKER_BUILD_TAG) $(RELEASE)
	@make DOCKER_URI=$(RELEASE) docker:push
	@echo "Retagged image as $(RELEASE) and pushed to $(DOCKER_REGISTRY)"
endif

docker-push-rhel:
	$(eval RHEL_IMAGE := $(DOCKER_REGISTRY)/$(DOCKER_NAMESPACE)/$(DOCKER_IMAGE):$(DOCKER_BUILD_TAG_RHEL))
	@make DOCKER_URI=$(RHEL_IMAGE) docker:push
ifneq ($(RETAG),)
	$(eval RELEASE := $(DOCKER_REGISTRY)/$(DOCKER_NAMESPACE)/$(DOCKER_IMAGE):$(RELEASE_TAG_RHEL))
	docker tag $(DOCKER_REGISTRY)/$(DOCKER_NAMESPACE)/$(DOCKER_IMAGE):$(DOCKER_BUILD_TAG_RHEL) $(RELEASE)
	@make DOCKER_URI=$(RELEASE) docker:push
	@echo "Retagged image as $(RELEASE) and pushed to $(DOCKER_REGISTRY)"
endif