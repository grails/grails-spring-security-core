#!/usr/bin/env bash

PROJECTS="grails-spring-security-group grails-spring-security-hierarchical-roles"
GORM_VERSIONS="6.0.9.RELEASE 6.1.1.RELEASE"

set -e

for project in $PROJECTS; do

    for gormVersion in $GORM_VERSIONS; do

        echo "running tests for project: $project with GORM version: $gormVersion"

        cd misc-functional-test-app/$project 
        
        rm -rf build

        rm -rf .gradle

        ./gradlew deleteS2QuickstartGeneratedFiles

        ./gradlew -PnewGormVersion=$gormVersion updateGormVersion

        ./gradlew check

        cd ../..

    done

done
