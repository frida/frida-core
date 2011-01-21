#!/bin/bash

case $# in
  1)
    case $1 in
      *-jhbuild)
        export FRIDA_ENVIRONMENT=jhbuild
        export FRIDA_TARGET=$(echo $1 | sed 's,-jhbuild$,,')
        ;;
      *)
        export FRIDA_ENVIRONMENT=normal
        export FRIDA_TARGET=$1
        ;;
    esac
    ;;
  *)
    echo "Format: $0 <TARGET>"
    exit 1
    ;;
esac

cd $(dirname $0)/..

bash --rcfile build/bashrc
