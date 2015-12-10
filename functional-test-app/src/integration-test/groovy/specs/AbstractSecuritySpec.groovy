package specs

import geb.driver.CachingDriverFactory
import geb.spock.GebReportingSpec
import grails.plugin.springsecurity.SpringSecurityUtils
import grails.test.mixin.integration.Integration
import org.springframework.security.authentication.encoding.MessageDigestPasswordEncoder
import pages.LoginPage
import spock.lang.Shared
import spock.lang.Stepwise

@Integration
@Stepwise
abstract class AbstractSecuritySpec extends GebReportingSpec {

	private @Shared boolean databaseReset = false

	void setup() {
		logout()

		// call resetDatabase() once per suite, before the first test; would
		// be better in a setupSpec() method, but can't make go() calls there
		if (!databaseReset) {
			resetDatabase()
			databaseReset = true
		}
	}

	void cleanup() {
		CachingDriverFactory.clearCache()
	}

	void cleanupSpec() {
		databaseReset = false
	}

	protected void resetDatabase() {
		go 'testData/reset'
	}

	protected String getContent(String url) {
		go url
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
		go SpringSecurityUtils.securityConfig.logout.filterProcessesUrl
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
