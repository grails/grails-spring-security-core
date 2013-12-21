package test

/**
 * @author <a href='mailto:th3morg@gmail.com'>Ryan Morgan</a>
 */
class TestRoleGroup {
	String name

	Set<TestRole> getRoles() {
		TestRoleGroupRoles.findAllByGroup(this).collect { it.role }
	}

	static constraints = {
		name blank: false, unique: true
	}
}
