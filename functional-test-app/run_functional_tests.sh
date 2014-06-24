#!/bin/bash
rm -rf ~/.gvm
curl -s get.gvmtool.net | bash
perl -i -p -e 's/gvm_auto_answer=false/gvm_auto_answer=true/' ~/.gvm/etc/config
source ~/.gvm/bin/gvm-init.sh
gvm install grails 2.3.9
gvm use grails 2.3.9

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"
set +xe
ant
