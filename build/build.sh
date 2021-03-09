#!/bin/bash
# Copyright Contributors to the Open Cluster Management project

set -e

export DOCKER_IMAGE_AND_TAG=${1}
export GOARCH=$(go env GOARCH)
make build-prod
make docker/build
