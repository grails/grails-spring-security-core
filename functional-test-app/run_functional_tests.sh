#!/usr/bin/env bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"

set -e

GRAILS_VERSIONS="3.0.11 3.1.0.RC1"
TEST_GROUPS="static annotation requestmap basic misc bcrypt"

rm -rf build

function generateBuildGradle {
	grailsVersion=$1

	rm -f build.gradle
	echo -e "$(<gradle/buildscript.inc)\n" >> build.gradle

	if [[ $grailsVersion =~ 3\.0\..+ ]]; then
		echo "$(<gradle/spring_dependency_management.inc)" >> build.gradle

		echo -e "\napply plugin: 'spring-boot'\n" >> build.gradle
	fi

	echo -e "apply from: '../gradle/testapp.gradle'" >> build.gradle

	echo -e "\ndependencies {" >> build.gradle
	if [[ $grailsVersion =~ 3\.0\..+ ]]; then
		echo -e "\tcompile 'org.grails.plugins:hibernate'" >> build.gradle
	else
		echo -e "\tcompile 'org.grails.plugins:hibernate4'" >> build.gradle
		echo -e "\tcompile 'org.grails:grails-core'" >> build.gradle
		echo -e "\tprofile 'org.grails.profiles:web:$grailsVersion'" >> build.gradle
	fi
	echo -e "\tcompile 'org.grails.plugins:cache'" >> build.gradle
	echo -e "\tcompile 'org.grails:grails-web-boot'" >> build.gradle
	echo -e "\tcompile 'org.hibernate:hibernate-ehcache'" >> build.gradle
	echo "}" >> build.gradle

	echo "$(<gradle/integrationTest.inc)" >> build.gradle
}

function runTestGroup {
	testGroup=$1
	_grailsVersion=$2

	echo $testGroup > testconfig

	./gradlew -q cleanBuild check --stacktrace

	mv build/reports/tests build/reports/tests-$testGroup-$_grailsVersion
	mv build/geb-reports build/geb-reports-$testGroup-$_grailsVersion
	mv build/test-results build/test-results-$testGroup-$_grailsVersion
}

for grailsVersion in $GRAILS_VERSIONS; do

	_grailsVersion=${grailsVersion//\./_}

	echo grailsVersion=$grailsVersion > gradle.properties
	cp gradle.properties gradle$_grailsVersion.properties

	generateBuildGradle $grailsVersion
	cp build.gradle build$_grailsVersion.gradle

	rm -rf .gradle

	for testGroup in $TEST_GROUPS; do
		runTestGroup $testGroup $_grailsVersion
	done

done
