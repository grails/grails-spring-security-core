import junit.framework.TestSuite

/**
 * Suite for tests that use the Controller annotation configuration.
 */
class AnnotationSuite extends functionaltestplugin.FunctionalTestCase {

	/**
	 * Runs the tests in order since the security tests don't cleanup afterwards.
	 */
	static TestSuite suite() {
		new TestSuite([RoleTest, UserTest, AnnotationSecurityTest] as Class[])
	}
}
