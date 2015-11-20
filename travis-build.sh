#!/bin/bash
set -e

curl -s get.sdkman.io | bash
perl -i -p -e 's/sdkman_auto_answer=false/sdkman_auto_answer=true/' ~/.sdkman/etc/config
source "$HOME/.sdkman/bin/sdkman-init.sh"
sdk install grails

grails test-app
grails install

cd secured
grails test-app
cd ..

#./integration-test-app/run_integration_tests.sh
#./functional-test-app/run_functional_tests.sh
#./grailsw doc --pdf --non-interactive
