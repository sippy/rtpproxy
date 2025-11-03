#!/bin/sh

set -e

platformopts() {
  out=""
  case "${BASE_IMAGE}" in
  ubuntu:*)
    case "${TARGETPLATFORM}" in
    linux/arm64/v8)
      echo "QEMU_CPU=cortex-a53"
      ;;
    esac
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
