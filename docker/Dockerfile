FROM --platform=$TARGETPLATFORM debian:12-slim as build
LABEL maintainer="Maksym Sobolyev <sobomax@sippysoft.com>"

USER root

# Set Environment Variables
ENV DEBIAN_FRONTEND noninteractive

WORKDIR /rtpproxy
COPY . /rtpproxy/

#install basic components
RUN /rtpproxy/docker/build.sh
RUN ls -l /usr/local/bin/rtpproxy*
RUN ls -l /usr/local/bin/makeann*
RUN ls -l /usr/local/lib/*rtpproxy*
