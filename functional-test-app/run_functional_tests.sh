#!/usr/bin/env bash

if [ -z "$GVM_DIR" ]; then
	GVM_DIR='~/.gvm'
fi

use_grails_versions="$@"
if [ -z "$use_grails_versions" ]; then
	use_grails_versions="2.4.5"
fi

source "$GVM_DIR/bin/gvm-init.sh"

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"

function runTest {
	GRAILS_VERSION="$1"
	set +xe
	gvm use grails $GRAILS_VERSION
	set -xe

	./upgrade_app.sh

	rm -rf target
	grails -refresh-dependencies clean --non-interactive
	grails compile --non-interactive

	TESTGROUPS="static annotation requestmap basic misc bcrypt"
	for TESTGROUP in $TESTGROUPS; do
		echo $TESTGROUP > testconfig
		grails test-app --non-interactive -functional
		mv target/test-reports target/test-reports-$TESTGROUP
	done
}

for use_grails_version in $use_grails_versions; do
	runTest "$use_grails_version"
done
