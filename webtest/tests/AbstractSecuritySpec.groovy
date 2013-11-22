import geb.spock.GebReportingSpec

import org.springframework.security.authentication.encoding.MessageDigestPasswordEncoder

import pages.LoginPage
import pages.LogoutPage

abstract class AbstractSecuritySpec extends GebReportingSpec {

	def cleanup() {
		logout()
	}

	protected String getContent(String url) {
		go browser.baseUrl + url
		$().text()
	}

	protected String getSessionValue(String name) {
		getContent 'hack/getSessionValue?name=' + name
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
