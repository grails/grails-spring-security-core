rm -rf docs/manual
grails doc --pdf --stacktrace | grep -v javadoc
#grails doc --stacktrace | grep -v javadoc
rm -rf docs/manual/api
rm -rf docs/manual/gapi
grails add-tracking
