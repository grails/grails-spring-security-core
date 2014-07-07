#!/bin/bash
use_grails_versions="$@"
if [ -z "$use_grails_versions" ]; then
	use_grails_versions="2.4.2"
fi

source ~/.gvm/bin/gvm-init.sh

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"

function run_test {
	GRAILS_VERSION="$1"
	set +xe
	gvm use grails $GRAILS_VERSION
	set -xe
	./upgrade_app.sh
	ant
}

for use_grails_version in "$use_grails_versions"; do
	run_test "$use_grails_version"
done