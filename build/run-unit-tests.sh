#!/bin/bash
set -e

export DOCKER_IMAGE_AND_TAG=${1}
# make docker/run
make sonar/go
