package test

import org.apache.commons.lang.builder.HashCodeBuilder

/**
 * @author <a href='mailto:th3morg@gmail.com'>Ryan Morgan</a>
 */
class TestUserRoleGroup implements Serializable {

	private static final long serialVersionUID = 1

	TestUser user
	TestRoleGroup roleGroup

	boolean equals(other) {
		if (!(other instanceof TestUserRoleGroup)) {
			return false
		}

		other.user?.id == user?.id && other.roleGroup?.id == roleGroup?.id
	}

	int hashCode() {
		def builder = new HashCodeBuilder()
		if (user) builder.append(user.id)
		if (roleGroup) builder.append(roleGroup.id)
		builder.toHashCode()
	}

	static TestUserRoleGroup get(long userId, long roleGroupId) {
		TestUserRoleGroup.where {
			user == TestUser.load(userId) &&
			roleGroup == TestRoleGroup.load(roleGroupId)
		}.get()
	}

	static boolean exists(long userId, long roleGroupId) {
		TestUserRoleGroup.where {
			user == TestUser.load(userId) &&
			roleGroup == TestRoleGroup.load(roleGroupId)
		}.count() > 0
	}

	static TestUserRoleGroup create(TestUser user, TestRoleGroup roleGroup, boolean flush = false) {
		def instance = new TestUserRoleGroup(user: user, roleGroup: roleGroup)
		instance.save(flush: flush, insert: true)
		instance
	}

	static boolean remove(TestUser u, TestRoleGroup rg, boolean flush = false) {
		int rowCount = TestUserRoleGroup.where {
			user == TestUser.load(u.id) &&
			roleGroup == TestRoleGroup.load(rg.id)
		}.deleteAll()

		if (flush) { TestUserRoleGroup.withSession { it.flush() } }

		rowCount > 0
	}

	static void removeAll(TestUser u, boolean flush = false) {
		TestUserRoleGroup.where {
			user == TestUser.load(u.id)
		}.deleteAll()

		if (flush) { TestUserRoleGroup.withSession { it.flush() } }
	}

	static void removeAll(TestRoleGroup rg, boolean flush = false) {
		TestUserRoleGroup.where {
			roleGroup == TestRoleGroup.load(rg.id)
		}.deleteAll()

		if (flush) { TestUserRoleGroup.withSession { it.flush() } }
	}

	static constraints = {
		user validator: { TestUser u, TestUserRoleGroup ug ->
			if (ug.roleGroup == null) return
			boolean existing = false
			TestUserRoleGroup.withNewSession {
				existing = TestUserRoleGroup.exists(u.id, ug.roleGroup.id)
			}
			if (existing) {
				return 'userGroup.exists'
			}
		}
	}

	static mapping = {
		id composite: ['roleGroup', 'user']
		version false
	}
}
