#!/bin/bash
source ~/.gvm/bin/gvm-init.sh
gvm use grails 3.0.4

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"

set -xe
grails compile --non-interactive
grails test-app --non-interactive
