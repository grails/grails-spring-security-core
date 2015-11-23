#!/usr/bin/env bash

set -e

rm -rf build
./gradlew clean check assemble install

src/integration-test/integration-test-app/run_integration_tests.sh

src/functional-test/functional-test-app/run_functional_tests.sh
