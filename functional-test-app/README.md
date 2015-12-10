Functional tests for spring-security-core
=========================================

Functional tests use [Geb](http://www.gebish.org/)

Prerequisites:
- [phantomjs](http://phantomjs.org/) for running Geb tests in headless mode (default)
- [chromedriver](https://code.google.com/p/selenium/wiki/ChromeDriver) (optional, if you want to use Chrome instead)

On Mac OSX, you can install phantomjs and chromedriver with homebrew
```
brew install phantomjs
brew install chromedriver
```

Running tests
=============
```
./run_functional_tests.sh
```
This runs the functional tests with multiple versions of Grails (currently 3.0 and 3.1).

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
