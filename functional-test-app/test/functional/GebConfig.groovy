// See: http://www.gebish.org/manual/current/configuration.html

import org.openqa.selenium.chrome.ChromeDriver
import org.openqa.selenium.firefox.FirefoxDriver
import org.openqa.selenium.phantomjs.PhantomJSDriver
import org.openqa.selenium.remote.DesiredCapabilities

//System.setProperty 'webdriver.chrome.driver', 'c:/dev/chromedriver.exe'
//System.setProperty 'phantomjs.binary.path', ''

//driver = { new ChromeDriver() }
driver = { new PhantomJSDriver(new DesiredCapabilities()) }

// standalone usage, running tests in IDE
if (!System.getProperty("grails.env")) {
	reportsDir = new File("target/geb-reports")
	baseUrl = 'http://localhost:8238/functional-test-app/'
	driver = { new ChromeDriver() }
}

environments {

	// run as 'grails -Dgeb.env=phantomjs test-app'
	// See: http://code.google.com/p/selenium/wiki/HtmlUnitDriver
	htmlunit {
		driver = { new PhantomJSDriver(new DesiredCapabilities()) }
	}

	// run as 'grails -Dgeb.env=chrome test-app'
	// See: http://code.google.com/p/selenium/wiki/ChromeDriver
	chrome {
		driver = { new ChromeDriver() }
	}

	// run as 'grails -Dgeb.env=firefox test-app'
	// See: http://code.google.com/p/selenium/wiki/FirefoxDriver
	firefox {
		driver = { new FirefoxDriver() }
	}
}


