// See: http://www.gebish.org/manual/current/configuration.html

import org.openqa.selenium.chrome.ChromeDriver
import org.openqa.selenium.firefox.FirefoxDriver
import org.openqa.selenium.phantomjs.PhantomJSDriver
import org.openqa.selenium.remote.DesiredCapabilities

import geb.report.ReportState
import geb.report.Reporter
import geb.report.ReportingListener

//System.setProperty 'webdriver.chrome.driver', 'c:/dev/chromedriver.exe'
//System.setProperty 'phantomjs.binary.path', ''

//driver = { new ChromeDriver() }
driver = { new PhantomJSDriver(new DesiredCapabilities()) }

reportsDir = new File('build/geb-reports')
baseUrl = 'http://localhost:8238/'
quitCachedDriverOnShutdown = false

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

reportingListener = new ReportingListener() {
	void onReport(Reporter reporter, ReportState reportState, List<File> reportFiles) {
		reportFiles.each {
			println "Report taken: $it.absolutePath"
		}
	}
}
