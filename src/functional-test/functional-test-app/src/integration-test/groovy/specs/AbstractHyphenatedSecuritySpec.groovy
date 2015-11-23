package specs

abstract class AbstractHyphenatedSecuritySpec extends AbstractSecuritySpec {

	protected void resetDatabase() {
		go browser.baseUrl + 'test-data/reset'
		go browser.baseUrl + 'test-data/add-test-users'
	}

	protected String getSessionValue(String name) {
		getContent 'hack/get-session-value?name=' + name
	}

	protected void login(String username) {
		super.login username, 'password'
	}

	protected String getUserProperty(String user, String propertyName) {
		getContent "hack/get-user-property?user=$user&propName=$propertyName"
	}
}
