package test

import org.apache.commons.lang.builder.HashCodeBuilder

class TestUserRole implements Serializable {

	TestUser user
	TestRole role

	boolean equals(other) {
		if (!(other instanceof TestUserRole)) {
			return false
		}

		other.user.id == user.id && other.role.id == role.id
	}

	int hashCode() {
		def builder = new HashCodeBuilder()
		if (user) builder.append(user.id)
		if (role) builder.append(role.id)
		builder.toHashCode()
	}

	static TestUserRole get(long userId, long roleId) {
		find 'from TestUserRole where user.id=:userId and role.id=:roleId',
			[userId: userId, roleId: roleId]
	}

	static TestUserRole create(TestUser user, TestRole role, boolean flush = false) {
		new TestUserRole(user: user, role: role).save(flush: flush, insert: true)
	}

	static boolean remove(TestUser user, TestRole role, boolean flush = false) {
		TestUserRole instance = TestUserRole.findByUserAndRole(user, role)
		instance ? instance.delete(flush: flush) : false
	}

	static void removeAll(TestUser user) {
		executeUpdate "DELETE FROM TestUserRole WHERE user=:user", [user: user]
	}

	static mapping = {
		id composite: ['role', 'user']
		version false
	}
}
