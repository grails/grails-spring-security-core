#!/bin/bash

# installs grails version that isn't registered in gvm
function install_recent_grails {
	GRAILS_VERSION=$1
	(
	cd /tmp
	curl -O http://dist.springframework.org.s3.amazonaws.com/release/GRAILS/grails-${GRAILS_VERSION}.zip
	unzip grails-${GRAILS_VERSION}.zip -d ~/.gvm/grails/ 
	mv ~/.gvm/grails/{grails-${GRAILS_VERSION},${GRAILS_VERSION}}
	rm grails-${GRAILS_VERSION}.zip
	)	
}

rm -rf ~/.gvm
curl -s get.gvmtool.net | bash
perl -i -p -e 's/gvm_auto_answer=false/gvm_auto_answer=true/' ~/.gvm/etc/config
source ~/.gvm/bin/gvm-init.sh
gvm install grails 2.3.9
#gvm install grails 2.4.0
install_recent_grails 2.4.2
exit 0
