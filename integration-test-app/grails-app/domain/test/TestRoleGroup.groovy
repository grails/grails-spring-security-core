package test

class TestRoleGroup implements Serializable {

	private static final long serialVersionUID = 1

	String name

	TestRoleGroup(String name) {
		this()
		this.name = name
	}

	@Override
	int hashCode() {
		name?.hashCode() ?: 0
	}

	@Override
	boolean equals(other) {
		is(other) || (other instanceof TestRoleGroup && other.name == name)
	}

	@Override
	String toString() {
		name
	}

	Set<TestRole> getRoles() {
		TestRoleGroupRoles.findAllByRoleGroup(this)*.role
	}

	static constraints = {
		name blank: false, unique: true
	}

	static mapping = {
		cache true
	}
}
