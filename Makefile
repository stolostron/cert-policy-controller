# IBM Confidential
# OCO Source Materials
#
# (C) Copyright IBM Corporation 2018 All Rights Reserved
# The source code for this program is not published or otherwise divested of its trade secrets, irrespective of what has been deposited with the U.S. Copyright Office.

include Configfile

-include $(shell curl -H 'Authorization: token ${GITHUB_TOKEN}' -H 'Accept: application/vnd.github.v4.raw' -L https://api.github.com/repos/open-cluster-management/build-harness-extensions/contents/templates/Makefile.build-harness-bootstrap -o .build-harness-bootstrap; echo .build-harness-bootstrap)

.PHONY: default
default::
	@echo "Build Harness Bootstrapped"

.PHONY: all test dependencies build-prod image rhel-image manager run deploy install \
fmt vet generate go-coverage

all: test manager

# Run tests
unit-test: generate fmt vet
	curl -sL https://go.kubebuilder.io/dl/2.0.0-alpha.1/${GOOS}/${GOARCH} | tar -xz -C /tmp/

	sudo mv /tmp/kubebuilder_2.0.0-alpha.1_${GOOS}_${GOARCH} /usr/local/kubebuilder
	go test ./pkg/... ./cmd/... -v -coverprofile cover.out

dependencies:
	go mod tidy
	go mod download	

build-prod:
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -a -tags netgo -o ./cert-policy ./cmd/manager

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

go-coverage:
	$(shell go test -coverprofile=coverage.out -json ./...\
		$$(go list ./... | \
			grep -v '/vendor/' | \
			grep -v '/docs/' \
		) > report.json)
	gosec -fmt sonarqube -out gosec.json -no-fail ./...
	sonar-scanner --debug || echo "Sonar scanner is not available"
