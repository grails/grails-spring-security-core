#!/usr/bin/env bash

rm -rf target

# upgrade application
grails create-app --inplace --skip-wrapper functional-test-app

# revert some files after upgrade
git checkout -- grails-app/conf/{BootStrap.groovy,BuildConfig.groovy,Config.groovy,DataSource.groovy,UrlMappings.groovy,spring/resources.groovy} grails-app/views/{error.gsp,index.gsp}
rm -rf grails-app/assets
rm -f grails-app/conf/ApplicationResources.groovy
rm -f grails-app/views/layouts/main.gsp
rm -f web-app/images/springsource.png
