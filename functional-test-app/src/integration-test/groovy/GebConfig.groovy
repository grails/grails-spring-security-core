import org.openqa.selenium.chrome.ChromeDriver
import org.openqa.selenium.firefox.FirefoxDriver
import org.openqa.selenium.htmlunit.HtmlUnitDriver
import org.openqa.selenium.phantomjs.PhantomJSDriver
import org.openqa.selenium.remote.DesiredCapabilities

// See: http://www.gebish.org/manual/current/configuration.html
quitCachedDriverOnShutdown = true

environments {
	// See: http://code.google.com/p/selenium/wiki/HtmlUnitDriver
	// run as 'grails -Dgeb.env=htmlUnit test-app'
	htmlUnit {
		driver = { new HtmlUnitDriver() }
	}
	// run as 'grails -Dgeb.env=chrome -Dwebdriver.chrome.driver=/Users/sdelamo/Applications/chromedriver test-app'
	// See: http://code.google.com/p/selenium/wiki/ChromeDriver
	chrome {
		driver = { new ChromeDriver() }
	}
	// run as 'grails -Dgeb.env=firefox test-app'
	// See: http://code.google.com/p/selenium/wiki/FirefoxDriver
	firefox {
		driver = { new FirefoxDriver() }
	}
	// run as 'grails -Dgeb.env=phantomJs -Dphantomjs.binary.path=/Users/sdelamo/Applications/phantomjs-2.1.1-macosx/bin/phantomjs test-app'
	phantomJs {
		driver = { new PhantomJSDriver(new DesiredCapabilities()) }
	}
}
