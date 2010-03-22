package test

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class TestUser {

	static transients = ['pass', 'roleNames']

	String loginName
	String passwrrd
	boolean enabld

	String pass = '[secret]'

	Set<TestRole> getRoles() { TestUserRole.findAllByUser(this).collect { it.role } }

	Collection<String> getRoleNames() { roles*.auth }

	static constraints = {
		loginName blank: false, unique: true
		passwrrd blank: false
	}
}
