#!/usr/bin/env bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"

rm -rf build
./gradlew classes

TESTGROUPS="static annotation requestmap basic misc bcrypt"
for TESTGROUP in $TESTGROUPS; do
	echo $TESTGROUP > testconfig
	./gradlew check
	mv build/reports/tests build/reports/tests-$TESTGROUP
	mv build/geb-reports build/geb-reports-$TESTGROUP
	mv build/test-results build/test-results-$TESTGROUP
done
