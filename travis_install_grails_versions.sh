#!/bin/bash

function install_grails {
	GRAILS_VERSION=$1
	if [ -f $HOME/.grails/wrapper/$GRAILS_VERSION/grails-$GRAILS_VERSION/bin/grails ]; then
		cd ~/.sdkman/grails
		if [ ! -e $GRAILS_VERSION ]; then
			# reuse grails version from wrapper
			ln -s $HOME/.grails/wrapper/$GRAILS_VERSION/grails-$GRAILS_VERSION $GRAILS_VERSION
			cd $GRAILS_VERSION/bin
			if [ ! -x grails ]; then
				chmod a+rx grails
			fi
		fi
	else
		sdk install grails $GRAILS_VERSION
		if [ $? -ne 0 ]; then
			# grails version not available in sdkman yet, download directly from s3
			set -e
			(
			set -e
			cd /tmp
			curl -O http://dist.springframework.org.s3.amazonaws.com/release/GRAILS/grails-${GRAILS_VERSION}.zip
			unzip grails-${GRAILS_VERSION}.zip -d ~/.sdkman/grails/
			mv ~/.sdkman/grails/{grails-${GRAILS_VERSION},${GRAILS_VERSION}}
			rm grails-${GRAILS_VERSION}.zip
			)
		fi
	fi
}

if [ ! -f ~/.sdkman/etc/config ]; then
	rm -rf ~/.sdkman
	curl -s get.sdkman.io | bash
	perl -i -p -e 's/sdkman_auto_answer=false/sdkman_auto_answer=true/' ~/.sdkman/etc/config
else
    sdk selfupdate force
fi

source ~/.sdkman/bin/sdkman-init.sh

install_grails 2.5.1

exit 0
