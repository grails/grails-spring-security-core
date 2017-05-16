#!/usr/bin/env bash

set -e

echo "Generating Docs"

./gradlew docs --stacktrace

git config --global user.name "$GIT_NAME"
git config --global user.email "$GIT_EMAIL"
git config --global credential.helper "store --file=~/.git-credentials"
echo "https://$GH_TOKEN:@github.com" > ~/.git-credentials

echo "Publishing Documentation"

git clone https://${GH_TOKEN}@github.com/grails-plugins/grails-spring-security-core.git -b gh-pages gh-pages --single-branch > /dev/null

cd gh-pages

git rm v3.3/spring-security-core-*.epub
mv  ../build/docs/spring-security-core-*.epub v3
git add v3.3/spring-security-core-*.epub

git rm v3.3/spring-security-core-*.pdf
mv ../build/docs/spring-security-core-*.pdf v3
git add v3.3/spring-security-core-*.pdf

mv ../build/docs/index.html v3
git add v3.3/index.html

mv ../build/docs/ghpages.html index.html
git add index.html

git commit -a -m "Updating docs for Travis build: https://travis-ci.org/$TRAVIS_REPO_SLUG/builds/$TRAVIS_BUILD_ID"
git push origin HEAD

cd ..

rm -rf gh-pages