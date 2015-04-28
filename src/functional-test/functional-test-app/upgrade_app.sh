#!/bin/bash
rm -rf target

# upgrade application
grails create-app --inplace functional-test-app

# revert some files after upgrade
git checkout -- grails-app/conf/{Config.groovy,BootStrap.groovy,UrlMappings.groovy} grails-app/views/error.gsp

# customize some files after upgrade
cat > /tmp/inputfile.txt <<EOF
	String gebVersion = '0.9.3'
	String seleniumVersion = '2.42.2'

	dependencies {
		test "org.seleniumhq.selenium:selenium-chrome-driver:\$seleniumVersion"
		test "org.seleniumhq.selenium:selenium-firefox-driver:\$seleniumVersion"
		test 'com.github.detro:phantomjsdriver:1.2.0', {
			transitive = false
		}
        test "org.gebish:geb-spock:\$gebVersion"
EOF
perl -i -p -e 'open FILE, "</tmp/inputfile.txt"; my($input)=do { local $/; <FILE> }; s/(dependencies {)/$input/' grails-app/conf/BuildConfig.groovy

cat > /tmp/inputfile.txt <<EOF
		test ":geb:\$gebVersion"

		runtime ":spring-security-core:2.0-RC4"
EOF
perl -i -p -e 'open FILE, "</tmp/inputfile.txt"; my($input)=do { local $/; <FILE> }; s/(plugins {)/$1\n$input/' grails-app/conf/BuildConfig.groovy

perl -i -p -e 's/cache.use_second_level_cache = true/cache.use_second_level_cache = false/' grails-app/conf/DataSource.groovy

cat >> grails-app/conf/BuildConfig.groovy <<EOF

grails.project.fork=false

def file = new File('testconfig')
String testconfig = file.exists() ? file.text.trim() : ''
switch (testconfig) {
	case 'annotation':
		grails.testing.patterns = ['Role', 'User', 'AnnotationSecurity']
		break
	case 'basic':
		grails.testing.patterns = ['Role', 'User', 'BasicAuthSecurity']
		break
	case 'bcrypt':
		grails.testing.patterns = ['BCrypt']
		break
	case 'misc':
		grails.testing.patterns = ['Misc', 'Disable']
		break
	case 'requestmap':
		grails.testing.patterns = ['Requestmap', 'Role', 'User', 'RequestmapSecurity']
		break
	case 'static':
		grails.testing.patterns = ['Role', 'User', 'StaticSecurity']
		break
}
grails.server.port.http = 8238
EOF