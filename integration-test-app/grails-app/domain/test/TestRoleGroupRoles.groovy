package test

import grails.gorm.DetachedCriteria
import groovy.transform.ToString

import org.apache.commons.lang.builder.HashCodeBuilder

@ToString(cache=true, includeNames=true, includePackage=false)
class TestRoleGroupRoles implements Serializable {

	private static final long serialVersionUID = 1

	TestRoleGroup roleGroup
	TestRole role

	TestRoleGroupRoles(TestRoleGroup g, TestRole r) {
		this()
		roleGroup = g
		role = r
	}

	@Override
	boolean equals(other) {
		if (!(other instanceof TestRoleGroupRoles)) {
			return false
		}

		other.role?.id == role?.id && other.roleGroup?.id == roleGroup?.id
	}

	@Override
	int hashCode() {
		def builder = new HashCodeBuilder()
		if (roleGroup) builder.append(roleGroup.id)
		if (role) builder.append(role.id)
		builder.toHashCode()
	}

	static TestRoleGroupRoles get(long roleGroupId, long roleId) {
		criteriaFor(roleGroupId, roleId).get()
	}

	static boolean exists(long roleGroupId, long roleId) {
		criteriaFor(roleGroupId, roleId).count()
	}

	private static DetachedCriteria criteriaFor(long roleGroupId, long roleId) {
		TestRoleGroupRoles.where {
			roleGroup == TestRoleGroup.load(roleGroupId) &&
			role == TestRole.load(roleId)
		}
	}

	static TestRoleGroupRoles create(TestRoleGroup roleGroup, TestRole role, boolean flush = false) {
		def instance = new TestRoleGroupRoles(roleGroup: roleGroup, role: role)
		instance.save(flush: flush, insert: true)
		instance
	}

	static boolean remove(TestRoleGroup rg, TestRole r, boolean flush = false) {
		if (rg == null || r == null) return false

		int rowCount = TestRoleGroupRoles.where { roleGroup == rg && role == r }.deleteAll()

		if (flush) { TestRoleGroupRoles.withSession { it.flush() } }

		rowCount
	}

	static void removeAll(TestRole r, boolean flush = false) {
		if (r == null) return

		TestRoleGroupRoles.where { role == r }.deleteAll()

		if (flush) { TestRoleGroupRoles.withSession { it.flush() } }
	}

	static void removeAll(TestRoleGroup rg, boolean flush = false) {
		if (rg == null) return

		TestRoleGroupRoles.where { roleGroup == rg }.deleteAll()

		if (flush) { TestRoleGroupRoles.withSession { it.flush() } }
	}

	static constraints = {
		role validator: { TestRole r, TestRoleGroupRoles rg ->
			if (rg.roleGroup == null || rg.roleGroup.id == null) return
			boolean existing = false
			TestRoleGroupRoles.withNewSession {
				existing = TestRoleGroupRoles.exists(rg.roleGroup.id, r.id)
			}
			if (existing) {
				return 'roleGroup.exists'
			}
		}
	}

	static mapping = {
		id composite: ['roleGroup', 'role']
		version false
	}
}
