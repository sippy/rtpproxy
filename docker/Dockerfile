ARG BASE_IMAGE
FROM --platform=$TARGETPLATFORM $BASE_IMAGE as build
LABEL maintainer="Maksym Sobolyev <sobomax@sippysoft.com>"

USER root

# Set Environment Variables
ENV DEBIAN_FRONTEND noninteractive

WORKDIR /rtpproxy
COPY . /rtpproxy/

# Build & install everything
RUN /rtpproxy/docker/build.sh
RUN ls -l /usr/local/bin/rtpproxy*
RUN ls -l /usr/local/bin/makeann*
RUN ls -l /usr/local/lib/*rtpproxy*

ENTRYPOINT ["/usr/local/bin/rtpproxy_debug", "-fF"]
