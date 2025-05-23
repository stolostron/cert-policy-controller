# Copyright Contributors to the Open Cluster Management project

# Stage 1: Use image builder to build the target binaries
FROM registry.ci.openshift.org/stolostron/builder:go1.23-linux AS builder

ENV COMPONENT=cert-policy-controller
ENV REPO_PATH=/go/src/github.com/stolostron/${COMPONENT}
WORKDIR ${REPO_PATH}
COPY . .
RUN make build

# Stage 2: Copy the binaries from the image builder to the base image
FROM registry.access.redhat.com/ubi9/ubi-minimal:latest

ENV COMPONENT=cert-policy-controller
ENV REPO_PATH=/go/src/github.com/stolostron/${COMPONENT}
ENV OPERATOR=/usr/local/bin/${COMPONENT} \
    USER_UID=1001 \
    USER_NAME=${COMPONENT}

# install operator binary
COPY --from=builder ${REPO_PATH}/build/_output/bin/${COMPONENT} ${OPERATOR}

COPY --from=builder ${REPO_PATH}/build/bin /usr/local/bin
RUN  /usr/local/bin/user_setup

RUN microdnf install -y shadow-utils procps

ENTRYPOINT ["/usr/local/bin/entrypoint"]

USER ${USER_UID}

LABEL name="rhacm2/cert-policy-controller-rhel9"
LABEL summary="Monitor certificates on the cluster"
LABEL description="The CertificatePolicy kind compares the desired state of certificates with certificates on the cluster."
LABEL io.k8s.display-name="CertificatePolicy controller"
LABEL io.k8s.description="The CertificatePolicy kind compares the desired state of certificates with certificates on the cluster."
LABEL com.redhat.component="acm-cert-policy-controller-container"
LABEL io.openshift.tags="data,images"
