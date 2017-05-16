#!/usr/bin/env bash

PROJECTS="grails-spring-security-group grails-spring-security-hierarchical-roles"
GORM_VERSIONS="6.1.1.RELEASE 6.0.9.RELEASE"

set -e

for project in $PROJECTS; do
    
    echo "cd misc-functional-test-app/$project" 
    cd misc-functional-test-app/$project

    rm -rf build

    rm -rf .gradle

    echo "running tests for project: $project"

    ./gradlew clean check --stacktrace

    echo "cd ../.."

    cd ../..

done
