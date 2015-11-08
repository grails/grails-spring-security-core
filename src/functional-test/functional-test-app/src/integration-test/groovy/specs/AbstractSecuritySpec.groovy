package specs

import org.springframework.security.authentication.encoding.MessageDigestPasswordEncoder

import geb.spock.GebReportingSpec
import grails.test.mixin.integration.Integration
import grails.transaction.Rollback
import pages.LoginPage
import pages.LogoutPage
import spock.lang.Stepwise

@Integration
@Rollback
@Stepwise
abstract class AbstractSecuritySpec extends GebReportingSpec {

	void setupSpec() {
		resetDatabase()
	}

	void cleanup() {
		logout()
	}

	protected void resetDatabase() {
		go browser.baseUrl + 'testData/reset'
	}

	protected String getContent(String url) {
		go browser.baseUrl + url
		$().text()
	}

	protected String getSessionValue(String name) {
		getContent 'hack/getSessionValue?name=' + name
	}

	protected String getPageSource() {
		browser.driver.pageSource
	}

	protected void login(String user, String pwd, boolean remember = false) {
		to LoginPage
		username = user
		password = pwd
		if (remember) {
			rememberMe.click()
		}
		loginButton.click()
	}

	protected void logout() {
		to LogoutPage
		logoutButton.click()
		browser.clearCookies()
	}

	protected void assertContentContains(String expected) {
		assert $().text().contains(expected)
	}

	protected void assertContentDoesNotContain(String unexpected) {
		assert !$().text().contains(unexpected)
	}

	protected MessageDigestPasswordEncoder createSha256Encoder() {
		def passwordEncoder = new MessageDigestPasswordEncoder('SHA-256')
		passwordEncoder.iterations = 10000
		passwordEncoder
	}
}
