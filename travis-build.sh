#!/usr/bin/env bash

set -e

echo "travis tag: $TRAVIS_TAG"
rm -rf build

./run-all-tests.sh

if [[ $TRAVIS_BRANCH == 'master' && $TRAVIS_PULL_REQUEST == 'false' ]]; then

    echo "In branch master not a pull request"

    if [[ -n $TRAVIS_TAG ]]; then

    echo "this is a tag, deploy"

	./gradlew bintrayUpload --stacktrace

    publish-docs.sh

	fi

fi