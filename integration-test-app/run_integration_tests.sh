#!/usr/bin/env bash

if [ -z "$GVM_DIR" ]; then
	GVM_DIR='~/.gvm'
fi

source "$GVM_DIR/bin/gvm-init.sh"
gvm use grails 2.4.5

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"

set -xe

rm -rf target
grails compile --non-interactive
grails test-app --non-interactive
