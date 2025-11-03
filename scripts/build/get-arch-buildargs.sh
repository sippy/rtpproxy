#!/bin/sh

set -e
set -x

platformopts() {
  out=""
  case "${BASE_IMAGE}" in
  ubuntu:*)
    case "${TARGETPLATFORM}" in
    linux/arm64/v8)
      echo "QEMU_CPU=cortex-a53"
      ;;
    esac
    ;;
  debian:*)
    case "${TARGETPLATFORM}" in
    linux/arm/v5)
      if [ -z "${LIBS}" ]
      then
        echo "LIBS=-latomic"
      else
        echo "LIBS=${LIBS} -latomic"
      fi
      echo "LIB_DEPS=${LIB_DEPS} libatomic1"
      ;;
    esac
    ;;
  esac
}

case "${1}" in
platformopts)
  shift
  platformopts "${@}"
  ;;
*)
  echo "usage: `basename "${0}"` platformopts [opts]" 2>&1
  exit 1
  ;;
esac
