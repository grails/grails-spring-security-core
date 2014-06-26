#!/bin/bash
source ~/.gvm/bin/gvm-init.sh

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"

function run_test {
	GRAILS_VERSION=$1
	set +xe
	gvm use grails $GRAILS_VERSION
	set -xe
	./upgrade_app.sh
	ant
}

run_test 2.3.11
run_test 2.4.2