#!/bin/bash
use_grails_versions="$@"
if [ -z "$use_grails_versions" ]; then
	use_grails_versions="2.5.1"
fi

source ~/.sdkman/bin/sdkman-init.sh

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"

function run_test {
	GRAILS_VERSION="$1"
	set +xe
	sdk use grails $GRAILS_VERSION
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
	run_test "$use_grails_version"
done
