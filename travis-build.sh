#!/usr/bin/env bash
set -e

export EXIT_STATUS=0

echo "TRAVIS_TAG          : $TRAVIS_TAG"
echo "TRAVIS_BRANCH       : $TRAVIS_BRANCH"
echo "TRAVIS_PULL_REQUEST : $TRAVIS_PULL_REQUEST"
echo "Publishing archives for branch $TRAVIS_BRANCH"
rm -rf build

./gradlew :spring-security-core:clean || EXIT_STATUS=$?
./gradlew :spring-security-core:check || EXIT_STATUS=$?

if [[ $EXIT_STATUS -ne 0 ]]; then
    echo "Check failed"
    exit $EXIT_STATUS
fi

./gradlew :spring-security-core:install || EXIT_STATUS=$?

if [[ $EXIT_STATUS -ne 0 ]]; then
    echo "Check failed"
    exit $EXIT_STATUS
fi

./gradlew :integration-test-app:clean || EXIT_STATUS=$?
./gradlew :integration-test-app:check || EXIT_STATUS=$?

if [[ $EXIT_STATUS -ne 0 ]]; then
    echo "Integration tests failed"
    exit $EXIT_STATUS
fi

./gradlew :misc-functional-test-app/grails-spring-security-group:clean || EXIT_STATUS=$?
./gradlew :misc-functional-test-app/grails-spring-security-group:check || EXIT_STATUS=$?

if [[ $EXIT_STATUS -ne 0 ]]; then
    echo "Functional tests for Spring Security Group failed"
    exit $EXIT_STATUS
fi

./gradlew :misc-functional-test-app/grails-spring-security-hierarchical-roles:clean || EXIT_STATUS=$?
./gradlew :misc-functional-test-app/grails-spring-security-hierarchical-roles:check || EXIT_STATUS=$?

if [[ $EXIT_STATUS -ne 0 ]]; then
    echo "Functional tests for Spring Security Group Hierarchical roles failed"
    exit $EXIT_STATUS
fi

./gradlew functional-test-app:clean || EXIT_STATUS=$?
if [[ $EXIT_STATUS -ne 0 ]]; then
    echo "Functional tests for Spring Security - clean failed "
    exit $EXIT_STATUS
fi

./gradlew -DTESTCONFIG=static -Dgeb.env=htmlUnit functional-test-app:check || EXIT_STATUS=$?
if [[ $EXIT_STATUS -ne 0 ]]; then
    echo "Functional tests for Spring Security - TESTCONFIG:static - check failed "
    exit $EXIT_STATUS
fi

./gradlew -DTESTCONFIG=annotation -Dgeb.env=htmlUnit functional-test-app:check || EXIT_STATUS=$?
if [[ $EXIT_STATUS -ne 0 ]]; then
    echo "Functional tests for Spring Security - TESTCONFIG:annotation - check failed "
    exit $EXIT_STATUS
fi

./gradlew -DTESTCONFIG=requestmap -Dgeb.env=htmlUnit functional-test-app:check || EXIT_STATUS=$?
if [[ $EXIT_STATUS -ne 0 ]]; then
    echo "Functional tests for Spring Security - TESTCONFIG:requestmap - check failed "
    exit $EXIT_STATUS
fi

./gradlew -DTESTCONFIG=basic -Dgeb.env=htmlUnit functional-test-app:check || EXIT_STATUS=$?
if [[ $EXIT_STATUS -ne 0 ]]; then
    echo "Functional tests for Spring Security - TESTCONFIG:basic - check failed "
    exit $EXIT_STATUS
fi

./gradlew -DTESTCONFIG=misc -Dgeb.env=htmlUnit functional-test-app:check || EXIT_STATUS=$?
if [[ $EXIT_STATUS -ne 0 ]]; then
    echo "Functional tests for Spring Security - TESTCONFIG:misc - check failed "
    exit $EXIT_STATUS
fi

./gradlew -DTESTCONFIG=bcrypt -Dgeb.env=htmlUnit functional-test-app:check || EXIT_STATUS=$?
if [[ $EXIT_STATUS -ne 0 ]]; then
    echo "Functional tests for Spring Security - TESTCONFIG:bcrypt - check failed "
    exit $EXIT_STATUS
fi


# Only publish if the branch is on master, and it is not a PR
if [[ -n $TRAVIS_TAG ]] || [[ $TRAVIS_BRANCH == 'master' && $TRAVIS_PULL_REQUEST == 'false' ]]; then
  echo "Publishing archives for branch $TRAVIS_BRANCH"
  if [[ -n $TRAVIS_TAG ]]; then
      echo "Pushing build to Bintray"
      ./gradlew :spring-security-core:bintrayUpload || EXIT_STATUS=$?
  else
      echo "Publishing snapshot to OJO"
      ./gradlew :spring-security-core:artifactoryPublish || EXIT_STATUS=$?
  fi

  ./gradlew :spring-security-core:docs || EXIT_STATUS=$?

  git config --global user.name "$GIT_NAME"
  git config --global user.email "$GIT_EMAIL"
  git config --global credential.helper "store --file=~/.git-credentials"
  echo "https://$GH_TOKEN:@github.com" > ~/.git-credentials

  git clone https://${GH_TOKEN}@github.com/${TRAVIS_REPO_SLUG}.git -b gh-pages gh-pages --single-branch > /dev/null
  cd gh-pages

  # If this is the master branch then update the snapshot
  if [[ $TRAVIS_BRANCH == 'master' ]]; then

    mv ../plugin/build/docs/ghpages.html index.html
    git add index.html

    mkdir -p snapshot
    cp -r ../plugin/build/docs/. ./snapshot/
    git add snapshot/*

  fi

  # If there is a tag present then this becomes the latest
  if [[ -n $TRAVIS_TAG ]]; then
        git rm -rf latest/
        mkdir -p latest
        cp -r ../plugin/build/docs/. ./latest/
        git add latest/*

        version="$TRAVIS_TAG" # eg: v3.0.1
        version=${version:1} # 3.0.1
        majorVersion=${version:0:4} # 3.0.
        majorVersion="${majorVersion}x" # 3.0.x

        mkdir -p "$version"
        cp -r ../plugin/build/docs/. "./$version/"
        git add "$version/*"

        git rm -rf "$majorVersion"
        cp -r ../plugin/build/docs/. "./$majorVersion/"
        git add "$majorVersion/*"
  fi

  git commit -a -m "Updating docs for Travis build: https://travis-ci.org/$TRAVIS_REPO_SLUG/builds/$TRAVIS_BUILD_ID"
  git push origin HEAD
  cd ..
  rm -rf gh-pages
fi

exit $EXIT_STATUS



EXIT_STATUS=0
