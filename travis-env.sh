# Pushes images to integration if master and not a pull request.
if [ "$TRAVIS_BRANCH" = "master" ] && ! [ "$TRAVIS_EVENT_TYPE" = "pull_request" ]; then
    RETAG=true
    RELEASE_TAG=latest
    IMAGE_VERSION=4.1.0
    DOCKER_REGISTRY=hyc-cloud-private-integration-docker-local.artifactory.swg-devops.com
    NAMESPACE=ibmcom

    IMAGE_VERSION_RHEL="${IMAGE_VERSION}-rhel"
    RELEASE_TAG_RHEL="${RELEASE_TAG}-rhel"

    export DOCKER_REGISTRY="$DOCKER_REGISTRY"
    export DOCKER_NAMESPACE="$NAMESPACE"
    export RELEASE_TAG="$RELEASE_TAG"
    export DOCKER_BUILD_TAG="$IMAGE_VERSION"
    export DOCKER_BUILD_TAG_RHEL="$IMAGE_VERSION_RHEL"
    export RELEASE_TAG_RHEL="$RELEASE_TAG_RHEL"
    export RETAG="$RETAG"
fi
