#!/usr/bin/env bash

set -e

curl -s http://get.sdkman.io | bash
echo sdkman_auto_answer=true > ~/.sdkman/etc/config
echo "source \"$HOME/.sdkman/bin/sdkman-init.sh\""
source "$HOME/.sdkman/bin/sdkman-init.sh"

PROJECTS="grails-spring-security-group grails-spring-security-hierarchical-roles"
GORM_VERSIONS="6.1.1.RELEASE 6.0.9.RELEASE"


GRADLE_PROPERTIES_FILE=gradle.properties

function getProperty {
   PROP_KEY=$1
   PROP_VALUE=`cat $GRADLE_PROPERTIES_FILE | grep "$PROP_KEY" | cut -d'=' -f2`
   echo $PROP_VALUE
}


for project in $PROJECTS; do

    echo "cd misc-functional-test-app/$project"
    cd misc-functional-test-app/$project

    rm -rf build

    rm -rf .gradle

    GRAILS_VERSION=$(getProperty "grailsVersion")

    sdk install grails $GRAILS_VERSION

    echo "sdk use grails $GRAILS_VERSION"

    sdk use grails $GRAILS_VERSION

    echo "running tests for project: $project"

    ./gradlew clean check --stacktrace

    echo "cd ../.."

    cd ../..

done
