#!/usr/bin/env bash

set -e

echo "travis tag: $TRAVIS_TAG"
rm -rf build

./run-all-tests.sh

if [[ $TRAVIS_PULL_REQUEST == 'false' ]]; then

    if [[ -n $TRAVIS_TAG ]]; then

	    ./gradlew bintrayUpload --stacktrace

        ./publish-docs.sh

	fi
fi