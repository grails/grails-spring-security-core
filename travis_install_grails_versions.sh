#!/bin/bash
function install_grails {
	GRAILS_VERSION=$1
	if [ -f $HOME/.grails/wrapper/$GRAILS_VERSION/grails-$GRAILS_VERSION/bin/grails ]; then
		cd ~/.gvm/grails
		if [ ! -e $GRAILS_VERSION ]; then
			# reuse grails version from wrapper
			ln -s $HOME/.grails/wrapper/$GRAILS_VERSION/grails-$GRAILS_VERSION $GRAILS_VERSION
			cd $GRAILS_VERSION/bin
			if [ ! -x grails ]; then
				chmod a+rx grails
			fi
		fi
	else
		gvm install grails $GRAILS_VERSION
		if [ $? -ne 0 ]; then
			# grails version not available in gvm yet, download directly from s3
			set -e
			(
			set -e
			cd /tmp
			curl -O http://dist.springframework.org.s3.amazonaws.com/release/GRAILS/grails-${GRAILS_VERSION}.zip
			unzip grails-${GRAILS_VERSION}.zip -d ~/.gvm/grails/
			mv ~/.gvm/grails/{grails-${GRAILS_VERSION},${GRAILS_VERSION}}
			rm grails-${GRAILS_VERSION}.zip
			)
		fi
	fi
}


if [ ! -f ~/.gvm/etc/config ]; then
	# ~/.gvm is some golang related tool in Travis CI, just remove it and install gvm
	rm -rf ~/.gvm
	curl -s get.gvmtool.net | bash
	perl -i -p -e 's/gvm_auto_answer=false/gvm_auto_answer=true/' ~/.gvm/etc/config
fi

source ~/.gvm/bin/gvm-init.sh

install_grails 2.4.2

exit 0
