import junit.framework.TestSuite

/**
 * Suite for miscellaneous tests.
 */
class MiscSuite extends functionaltestplugin.FunctionalTestCase {

	/**
	 * Runs the tests in order since the security tests don't cleanup afterwards.
	 */
	static TestSuite suite() {
		new TestSuite([MiscTest, DisableTest] as Class[])
	}
}
