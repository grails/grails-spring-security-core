#!/bin/bash
set -e
rm -rf *.zip
./grailsw refresh-dependencies --non-interactive
./grailsw test-app --non-interactive
./grailsw package-plugin --non-interactive
./grailsw doc --pdf --non-interactive

filename=$(find . -name "grails-*.zip" | head -1)
filename=$(basename $filename)
plugin=${filename:7}
plugin=${plugin/.zip/}
plugin=${plugin/-SNAPSHOT/}
version="${plugin#*-}"; 
plugin=${plugin/"-$version"/}

echo "Publishing plugin grails-spring-security-core with version $version"

if [[ $TRAVIS_BRANCH == 'master' && $TRAVIS_REPO_SLUG == "grails-plugins/grails-spring-security-core" && $TRAVIS_PULL_REQUEST == 'false' ]]; then
  git config --global user.name "$GIT_NAME"
  git config --global user.email "$GIT_EMAIL"
  git config --global credential.helper "store --file=~/.git-credentials"
  echo "https://$GH_TOKEN:@github.com" > ~/.git-credentials

  if [[ $filename != *-SNAPSHOT* ]]
  then
    git clone https://${GH_TOKEN}@github.com/$TRAVIS_REPO_SLUG.git -b gh-pages gh-pages --single-branch > /dev/null
    cd gh-pages
    git rm -rf .
    cp -r ../docs/. ./
    git add *
    git commit -a -m "Updating docs for Travis build: https://travis-ci.org/$TRAVIS_REPO_SLUG/builds/$TRAVIS_BUILD_ID"
    git push origin HEAD
    cd ..
    rm -rf gh-pages
  else
    echo "SNAPSHOT version, not publishing docs"
  fi


  ./grailsw publish-plugin --no-scm --allow-overwrite --non-interactive
else
  echo "Not on master branch, so not publishing"
  echo "TRAVIS_BRANCH: $TRAVIS_BRANCH"
  echo "TRAVIS_REPO_SLUG: $TRAVIS_REPO_SLUG"
  echo "TRAVIS_PULL_REQUEST: $TRAVIS_PULL_REQUEST"
fi