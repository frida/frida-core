#!/bin/bash

case $# in
  1)
    export FRIDA_TARGET=$1
    ;;
  *)
    echo "Format: $0 <TARGET>"
    exit 1
    ;;
esac

cd $(dirname $0)/..

bash --rcfile build/bashrc

