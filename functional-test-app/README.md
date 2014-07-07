Functional tests for spring-security-core
=========================================

Functional tests use [Geb](http://www.gebish.org/)

Prerequisites:
- [phantomjs](http://phantomjs.org/) for running Geb tests in headless mode (default)
- [chromedriver](https://code.google.com/p/selenium/wiki/ChromeDriver) (for Chrome support)
- [GVM](http://gvmtool.net/) for switching between Grails versions

On Mac OSX, you can install phantomjs and chromedriver with homebrew
```
brew install phantomjs
brew install chromedriver
```

Running tests
=============
```
./run_functional_tests.sh 2.4.2 2.3.11
```
This runs the functional tests with Grails 2.4.2 and 2.3.11 versions.

Debugging tests
===============

Use IDE to execute single test method. You can also debug the test with the IDE.
By default, GebConfig contains config to use Chrome when tests are run outside grails in the IDE.

IDE support for running Geb tests is activated with these lines in GebConfig.groovy :
```
if (!System.getProperty("grails.env")) {
	reportsDir = new File("target/geb-reports")
	baseUrl = 'http://localhost:8238/functional-test-app/'
	driver = { new ChromeDriver() }
}
```
