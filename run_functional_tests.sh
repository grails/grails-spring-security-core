#!/usr/bin/env bash

GRAILS_VERSIONS="grails_3_3"
TEMPLATE_FOLDER="./functional-test-app"

# static annotation requestmap basic misc bcrypt
TEST_GROUPS="static annotation requestmap basic misc bcrypt"

# firefox, htmlUnit, chrome, phantomJs
GEBENV=$1
if [[ $GEBENV = "" ]]; then
    GEBENV=firefox
fi
# /Users/sdelamo/Applications/chromedriver
CHROMEDRIVER=$2
if [[ $CHROMEDRIVER = "" ]]; then
    CHROMEDRIVER=/Users/sdelamo/Applications/chromedriver
fi

# /Users/sdelamo/Applications/phantomjs-2.1.1-macosx/bin/phantomjs
PHANTOMJSDRIVER=$2
if [[ $PHANTOMJSDRIVER = "" ]]; then
    PHANTOMJSDRIVER=/Users/sdelamo/Applications/phantomjs-2.1.1-macosx/bin/phantomjs
fi

echo "GEB environment: $GEBENV"
echo "Chrome driver: $CHROMEDRIVER"
echo "PhantomJS driver: $PHANTOMJSDRIVER"

rm -rf $TEMPLATE_FOLDER/build
rm -rf $TEMPLATE_FOLDER/.gradle

function runTestGroup {
	testGroup=$1
	grailsVersion=$2
	echo "Running test group $testGroup for $grailsVersion"
        cd $TEMPLATE_FOLDER/$grailsVersion
	./gradlew -q -Dgeb.env=$GEBENV -Dwebdriver.chrome.driver=$CHROMEDRIVER -Dphantomjs.binary.path=$PHANTOMJSDRIVER -DTESTCONFIG=$testGroup cleanBuild check --stacktrace
    # mv build/reports/tests build/reports/tests-$testGroup-$grailsVersion
	# mv build/geb-reports build/geb-reports-$testGroup-$grailsVersion
	# mv build/test-results build/test-results-$testGroup-$grailsVersion
        cd ../..
}

for grailsVersion in $GRAILS_VERSIONS; do
    rm -rf $TEMPLATE_FOLDER/$grailsVersion/.gradle
    rm -rf $TEMPLATE_FOLDER/$grailsVersion/build
    
    for testGroup in $TEST_GROUPS; do
        runTestGroup $testGroup $grailsVersion
    done
done
