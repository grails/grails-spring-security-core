#!/usr/bin/env bash

set -e

rm -rf build

./gradlew -q clean check install --stacktrace

integration-test-app/run_integration_tests.sh

functional-test-app/run_functional_tests.sh
