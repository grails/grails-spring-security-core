#!/usr/bin/env bash

set -e

rm -rf build

./gradlew -q clean check install --stacktrace

integration-test-app/run_integration_tests.sh

./run-misc-functional-tests.sh

./copy_functional_tests_to_different_grails_versions.sh

./run_functional_tests.sh
