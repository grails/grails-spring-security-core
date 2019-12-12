#!/usr/bin/env bash
set -e

export EXIT_STATUS=0

echo "TRAVIS_TAG          : $TRAVIS_TAG"
echo "TRAVIS_BRANCH       : $TRAVIS_BRANCH"
echo "TRAVIS_PULL_REQUEST : $TRAVIS_PULL_REQUEST"


echo "*******************************"
echo "spring-security-core:check"
echo "*******************************"

./gradlew -Dgeb.env=firefoxHeadless :spring-security-core:check --console=plain || EXIT_STATUS=$?

if [ $EXIT_STATUS -ne 0 ]; then
  echo "spring-security-core:check failed => exit $EXIT_STATUS"
  exit $EXIT_STATUS
fi

echo "*******************************"
echo "spring-security-core:install"
echo "*******************************"

./gradlew :spring-security-core:install --console=plain  || EXIT_STATUS=$?

if [ $EXIT_STATUS -ne 0 ]; then
  echo "spring-security-core:install failed => exit $EXIT_STATUS"
  exit $EXIT_STATUS
fi

echo "*******************************"
echo "integration-test-app:check"
echo "*******************************"

./gradlew -Dgeb.env=firefoxHeadless :integration-test-app:check --console=plain  || EXIT_STATUS=$?

if [ $EXIT_STATUS -ne 0 ]; then
  echo "integration-test-app:check failed => exit $EXIT_STATUS"
  exit $EXIT_STATUS
fi

echo "*******************************"
echo "misc-group:check"
echo "*******************************"

./gradlew -Dgeb.env=firefoxHeadless :misc-group:check --console=plain  || EXIT_STATUS=$?

if [ $EXIT_STATUS -ne 0 ]; then
  echo "misc-group:check failed => exit $EXIT_STATUS"
  exit $EXIT_STATUS
fi

echo "*******************************"
echo "misc-hierarchical-roles:check"
echo "*******************************"

./gradlew  -Dgeb.env=firefoxHeadless :misc-hierarchical-roles:check --console=plain  || EXIT_STATUS=$?

if [ $EXIT_STATUS -ne 0 ]; then
  echo "misc-hierarchical-roles:check  failed => exit $EXIT_STATUS"
  exit $EXIT_STATUS
fi

echo "*******************************"
echo "static functional-test-app:check"
echo "*******************************"

./gradlew -DTESTCONFIG=static -Dgeb.env=firefoxHeadless functional-test-app:check  --console=plain || EXIT_STATUS=$?

if [ $EXIT_STATUS -ne 0 ]; then
  echo "static functional-test-app:check failed => exit $EXIT_STATUS"
  exit $EXIT_STATUS
fi

echo "*******************************"
echo "annotation functional-test-app:check"
echo "*******************************"

./gradlew -DTESTCONFIG=annotation -Dgeb.env=firefoxHeadless functional-test-app:check --console=plain  || EXIT_STATUS=$?

if [ $EXIT_STATUS -ne 0 ]; then
  echo "static functional-test-app:annotation failed => exit $EXIT_STATUS"
  exit $EXIT_STATUS
fi

echo "*******************************"
echo "requestmap functional-test-app:check"
echo "*******************************"

./gradlew -DTESTCONFIG=requestmap -Dgeb.env=firefoxHeadless functional-test-app:check --console=plain  || EXIT_STATUS=$?

if [ $EXIT_STATUS -ne 0 ]; then
  echo "requestmap functional-test-app:annotation failed => exit $EXIT_STATUS"
  exit $EXIT_STATUS
fi

echo "*******************************"
echo "basic functional-test-app:check"
echo "*******************************"

./gradlew -DTESTCONFIG=basic -Dgeb.env=firefoxHeadless functional-test-app:check --console=plain  || EXIT_STATUS=$?

if [ $EXIT_STATUS -ne 0 ]; then
  echo "basic functional-test-app:annotation failed => exit $EXIT_STATUS"
  exit $EXIT_STATUS
fi

echo "*******************************"
echo "misc functional-test-app:check"
echo "*******************************"

./gradlew -DTESTCONFIG=misc -Dgeb.env=firefoxHeadless functional-test-app:check --console=plain  || EXIT_STATUS=$?

if [ $EXIT_STATUS -ne 0 ]; then
  echo "misc functional-test-app:annotation failed => exit $EXIT_STATUS"
  exit $EXIT_STATUS
fi

echo "*******************************"
echo "putWithParams functional-test-app:check"
echo "*******************************"

./gradlew -DTESTCONFIG=putWithParams -Dgeb.env=firefoxHeadless functional-test-app:check --console=plain  || EXIT_STATUS=$?

if [ $EXIT_STATUS -ne 0 ]; then
  echo "putWithParams functional-test-app:annotation failed => exit $EXIT_STATUS"
  exit $EXIT_STATUS
fi

echo "*******************************"
echo "bcrypt functional-test-app:check"
echo "*******************************"

./gradlew -DTESTCONFIG=bcrypt -Dgeb.env=firefoxHeadless functional-test-app:check --console=plain  || EXIT_STATUS=$?

if [ $EXIT_STATUS -ne 0 ]; then
  echo "bcrypt functional-test-app:annotation failed => exit $EXIT_STATUS"
  exit $EXIT_STATUS
fi

echo "*******************************"
echo "issue503 functional-test-app:check"
echo "*******************************"

./gradlew -DTESTCONFIG=issue503 -Dgeb.env=firefoxHeadless functional-test-app:check --console=plain  || EXIT_STATUS=$?

if [ $EXIT_STATUS -ne 0 ]; then
  echo "issue503 functional-test-app:annotation failed => exit $EXIT_STATUS"
  exit $EXIT_STATUS
fi

if [ "${TRAVIS_JDK_VERSION}" == "openjdk11" ] ; then
  exit $EXIT_STATUS
fi

# Only publish if the branch is on master, and it is not a PR
if [[ -n $TRAVIS_TAG ]] || [[ $TRAVIS_BRANCH == 'master' && $TRAVIS_PULL_REQUEST == 'false' ]]; then
  echo "Publishing archives for branch $TRAVIS_BRANCH"
  if [[ -n $TRAVIS_TAG ]]; then
      echo "Pushing build to Bintray"
      ./gradlew :spring-security-core:bintrayUpload || EXIT_STATUS=$?
  else
      pluginversion=$(<version.txt)
      if [[ $pluginversion = *"BUILD-SNAPSHOT"* ]]; then
        echo "Publishing snapshot to OJO"
        ./gradlew :spring-security-core:artifactoryPublish || EXIT_STATUS=$?
      fi
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
