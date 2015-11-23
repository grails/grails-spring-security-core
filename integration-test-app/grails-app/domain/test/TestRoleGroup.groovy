package test

import groovy.transform.EqualsAndHashCode
import groovy.transform.ToString

@EqualsAndHashCode(includes='name')
@ToString(includes='name', includeNames=true, includePackage=false)
class TestRoleGroup implements Serializable {

	private static final long serialVersionUID = 1

	String name

	TestRoleGroup(String name) {
		this()
		this.name = name
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
