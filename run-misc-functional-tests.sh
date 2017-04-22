#!/usr/bin/env bash

PROJECTS="grails-spring-security-group grails-spring-security-hierarchical-roles"
GORM_VERSIONS="6.1.1.RELEASE 6.0.9.RELEASE"

set -e

for project in $PROJECTS; do
    
    echo "cd misc-functional-test-app/$project" 
    cd misc-functional-test-app/$project

    for gormVersion in $GORM_VERSIONS; do
       
        rm -rf build

        echo "running tests for project: $project with GORM version: $gormVersion"

        echo "./gradlew -PnewGormVersion=$gormVersion clean check --stacktrace"

        ./gradlew -PnewGormVersion=$gormVersion clean check --stacktrace

    done

    echo "cd ../.."
    cd ../..

done
