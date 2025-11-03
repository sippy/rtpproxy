# syntax=docker/dockerfile:1.7-labs

ARG BASE_IMAGE=debian:sid-slim
ARG LIBG722_IMAGE=sippylabs/libg722:latest-debian_sid-slim
ARG CCACHE_IMAGE=scratch
ARG CCACHE_BIN_IMAGE=ghcr.io/sobomax/ccache:latest-debian-12
FROM ${LIBG722_IMAGE} AS libg722
FROM ${CCACHE_BIN_IMAGE} AS ccache_bin
FROM ${BASE_IMAGE} AS build
LABEL maintainer="Maksym Sobolyev <sobomax@sippysoft.com>"

USER root

# Set Environment Variables
ENV DEBIAN_FRONTEND=noninteractive
COPY --from=libg722 /usr/local/lib/libg722.* /usr/local/lib/
COPY --from=libg722 /usr/local/include/g722* /usr/local/include/

# Build & install everything
ARG LIBSSL_APKG="libssl3"
ARG LIB_DEPS="libsrtp2-1 libbcg729-0 libgsm1 libsndfile1 libunwind8 ${LIBSSL_APKG}"
ARG CLANG_VER_OLD=15
ARG CLANG_VER_NEW=15
ARG BUILD_DEPS_COMM="file pkg-config  ccache git make libsrtp2-dev libbcg729-dev \
 libgsm1-dev libsndfile1-dev libunwind-dev libssl-dev curl gpg"
ARG BUILD_DEPS_OLD="${BUILD_DEPS_COMM} clang-${CLANG_VER_OLD} llvm-${CLANG_VER_OLD} \
 lld-${CLANG_VER_OLD}"
ARG BUILD_DEPS_NEW="${BUILD_DEPS_COMM} clang-${CLANG_VER_NEW} llvm-${CLANG_VER_NEW} \
 lld-${CLANG_VER_NEW}"

WORKDIR /tmp
ARG APT_INSTALL="apt-get install --no-install-recommends -y"
ARG APT_UPDATE="apt-get -y update -qq"
ARG TARGETPLATFORM
ARG BASE_IMAGE
ENV SET_ENV="./get-arch-buildargs.sh platformopts"
RUN --mount=type=bind,source=docker/install_depends.sh,target=install_depends.sh \
    --mount=type=bind,source=docker/clang_ver.sub,target=docker/clang_ver.sub \
    --mount=type=bind,source=scripts/build/get-arch-buildargs.sh,target=get-arch-buildargs.sh \
    --mount=type=bind,source=scripts/build/in_docker.sh,target=in_docker.sh \
      ./in_docker.sh ./install_depends.sh

COPY --exclude=.git* --link . /rtpproxy/

RUN mkdir -p /rtpproxy/ccache

FROM ${CCACHE_IMAGE} AS ccache
COPY --from=build /rtpproxy/ccache/ /rtpproxy/ccache/
FROM build
COPY --from=ccache /rtpproxy/ccache /rtpproxy/ccache
WORKDIR /rtpproxy
COPY --from=ccache_bin /usr/bin/ccache /usr/bin/ccache
ARG TARGETPLATFORM
ARG BASE_IMAGE
ENV SET_ENV="./scripts/build/get-arch-buildargs.sh platformopts"
RUN ./scripts/build/in_docker.sh /rtpproxy/docker/build.sh
RUN ls -l /usr/local/bin/rtpproxy*
RUN ls -l /usr/local/bin/makeann*
RUN ls -l /usr/local/lib/*rtpproxy*

ENTRYPOINT ["/usr/local/bin/rtpproxy_debug", "-fF"]
