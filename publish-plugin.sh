#!/usr/bin/env bash
set -e

filename=$(find build -name "spring-security-core-*.zip" | head -1)
filename=$(basename $filename)
plugin=${filename}
plugin=${plugin/.zip/}
plugin=${plugin/-SNAPSHOT/}
version="${plugin##*-}";
plugin=${plugin/"-$version"/}

if [[ $TRAVIS_BRANCH == 'master' && $TRAVIS_REPO_SLUG == "grails-plugins/grails-spring-security-core" && $TRAVIS_PULL_REQUEST == 'false' ]]; then

  echo "Publishing plugin $plugin with version $version"

  git config --global user.name "$GIT_NAME"
  git config --global user.email "$GIT_EMAIL"
  git config --global credential.helper "store --file=~/.git-credentials"
  echo "https://$GH_TOKEN:@github.com" > ~/.git-credentials

  if [[ $filename != *-SNAPSHOT* ]]
  then
    git clone https://${GH_TOKEN}@github.com/$TRAVIS_REPO_SLUG.git -b gh-pages gh-pages --single-branch > /dev/null
    cd gh-pages
    git rm -rf .
    cp -r ../docs/manual/. ./
    git add *
    git commit -a -m "Updating docs for Travis build: https://travis-ci.org/$TRAVIS_REPO_SLUG/builds/$TRAVIS_BUILD_ID"
    git push origin HEAD
    cd ..
    rm -rf gh-pages
  else
    echo "SNAPSHOT version, not publishing docs"
  fi


  grails publish-plugin --allow-overwrite --non-interactive
else
  echo "Not on master branch, so not publishing"
  echo "TRAVIS_BRANCH: $TRAVIS_BRANCH"
  echo "TRAVIS_REPO_SLUG: $TRAVIS_REPO_SLUG"
  echo "TRAVIS_PULL_REQUEST: $TRAVIS_PULL_REQUEST"
fi

