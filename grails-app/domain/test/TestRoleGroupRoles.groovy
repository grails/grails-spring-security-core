package test

import org.apache.commons.lang.builder.HashCodeBuilder

/**
 * @author <a href='mailto:th3morg@gmail.com'>Ryan Morgan</a>
 */
class TestRoleGroupRoles implements Serializable {

	private static final long serialVersionUID = 1

	TestRoleGroup roleGroup
	TestRole role

	boolean equals(other) {
		if (!(other instanceof TestRoleGroupRoles)) {
			return false
		}

		other.role?.id == role?.id && other.roleGroup?.id == roleGroup?.id
	}

	int hashCode() {
		def builder = new HashCodeBuilder()
		if (roleGroup) builder.append(roleGroup.id)
		if (role) builder.append(role.id)
		builder.toHashCode()
	}

	static TestRoleGroupRoles get(long roleGroupId, long roleId) {
		TestRoleGroupRoles.where {
			roleGroup == TestRoleGroup.load(roleGroupId) &&
			role == TestRole.load(roleId)
		}.get()
	}

	static boolean exists(long roleGroupId, long roleId) {
		TestRoleGroupRoles.where {
			roleGroup == TestRoleGroup.load(roleGroupId) &&
			role == TestRole.load(roleId)
		}.count() > 0
	}

	static TestRoleGroupRoles create(TestRoleGroup roleGroup, TestRole role, boolean flush = false) {
		def instance = new TestRoleGroupRoles(roleGroup: roleGroup, role: role)
		instance.save(flush: flush, insert: true)
		instance
	}

	static boolean remove(TestRoleGroup rg, TestRole r, boolean flush = false) {
		int rowCount = TestRoleGroupRoles.where {
			roleGroup == TestRoleGroup.load(rg.id) && role == TestRole.load(r.id)
		}.deleteAll()

		if (flush) { TestRoleGroupRoles.withSession { it.flush() } }

		rowCount > 0
	}

	static void removeAll(TestRole r, boolean flush = false) {
		TestRoleGroupRoles.where {
			role == TestRole.load(r.id)
		}.deleteAll()

		if (flush) { TestRoleGroupRoles.withSession { it.flush() } }
	}

	static void removeAll(TestRoleGroup rg, boolean flush = false) {
		TestRoleGroupRoles.where {
			roleGroup == TestRoleGroup.load(rg.id)
		}.deleteAll()

		if (flush) { TestRoleGroupRoles.withSession { it.flush() } }
	}

	static constraints = {
		role validator: { TestRole r, TestRoleGroupRoles rg ->
			if (rg.roleGroup == null) return
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
