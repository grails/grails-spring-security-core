Functional tests for spring-security-core
=========================================

Functional tests use [Geb](http://www.gebish.org/)

Prerequisites:
- [phantomjs](http://phantomjs.org/) for running Geb tests in headless mode (default)
- [chromedriver](https://code.google.com/p/selenium/wiki/ChromeDriver) (for Chrome support)
- Apache Ant
- GVM

On Mac OSX, you can install phantomjs and chromedriver with homebrew
```
brew install phantomjs
brew install chromedriver
```

Running tests
=============
```
gvm use grails 2.3.9
ant
```

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
