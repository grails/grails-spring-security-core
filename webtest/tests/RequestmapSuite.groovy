import junit.framework.TestSuite

/**
 * Suite for tests that use the Requestmap configuration.
 */
class RequestmapSuite extends functionaltestplugin.FunctionalTestCase {

	/**
	 * Runs the tests in order since the security tests don't cleanup afterwards.
	 */
	static TestSuite suite() {
		new TestSuite([RequestmapTest, RoleTest, UserTest, RequestmapSecurityTest] as Class[])
	}
}
