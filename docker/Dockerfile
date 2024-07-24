# syntax=docker/dockerfile:1.7-labs

ARG BASE_IMAGE
ARG CCACHE_IMAGE=scratch
FROM ${BASE_IMAGE} AS build
RUN mkdir -p /rtpproxy/ccache
FROM ${CCACHE_IMAGE} AS ccache
COPY --from=build /rtpproxy/ccache/ /rtpproxy/ccache/
FROM build
LABEL maintainer="Maksym Sobolyev <sobomax@sippysoft.com>"

USER root

# Set Environment Variables
ENV DEBIAN_FRONTEND=noninteractive

# Build & install everything
ARG LIB_DEPS="libsrtp2-1 libbcg729-0 libgsm1 libsndfile1 libunwind8 libssl3"
ARG CLANG_VER_OLD=15
ARG CLANG_VER_NEW=15
ARG BUILD_DEPS_COMM="file pkg-config  ccache git make libsrtp2-dev libbcg729-dev \
 libgsm1-dev libsndfile1-dev libunwind-dev libssl-dev curl gpg ca-certificates"
ARG BUILD_DEPS_OLD="${BUILD_DEPS_COMM} clang-${CLANG_VER_OLD} llvm-${CLANG_VER_OLD} \
 lld-${CLANG_VER_OLD}"
ARG BUILD_DEPS_NEW="${BUILD_DEPS_COMM} clang-${CLANG_VER_NEW} llvm-${CLANG_VER_NEW} \
 lld-${CLANG_VER_NEW}"

WORKDIR /tmp
ARG APT_INSTALL="apt-get install --no-install-recommends -y"
COPY docker/install_depends.sh /tmp
COPY docker/clang_ver.sub /tmp/docker/clang_ver.sub
ARG TARGETPLATFORM
RUN ./install_depends.sh

COPY --exclude=.git* --link . /rtpproxy/

ARG CCACHE_ROOT

WORKDIR /rtpproxy

COPY --from=ccache /rtpproxy/ccache /rtpproxy/ccache
RUN /rtpproxy/docker/build.sh
RUN ls -l /usr/local/bin/rtpproxy*
RUN ls -l /usr/local/bin/makeann*
RUN ls -l /usr/local/lib/*rtpproxy*

ENTRYPOINT ["/usr/local/bin/rtpproxy_debug", "-fF"]
