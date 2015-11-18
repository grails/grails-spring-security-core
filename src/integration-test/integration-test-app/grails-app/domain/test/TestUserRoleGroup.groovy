package test

import grails.gorm.DetachedCriteria
import groovy.transform.ToString
import org.apache.commons.lang.builder.HashCodeBuilder

@ToString(cache=true, includeNames=true, includePackage=false)
class TestUserRoleGroup implements Serializable {

	private static final long serialVersionUID = 1

	TestUser user
	TestRoleGroup roleGroup

	TestUserRoleGroup(TestUser u, TestRoleGroup rg) {
		this()
		user = u
		roleGroup = rg
	}

	@Override
	boolean equals(other) {
		if (!(other instanceof TestUserRoleGroup)) {
			return false
		}

		other.user?.id == user?.id && other.roleGroup?.id == roleGroup?.id
	}

	@Override
	int hashCode() {
		def builder = new HashCodeBuilder()
		if (user) builder.append(user.id)
		if (roleGroup) builder.append(roleGroup.id)
		builder.toHashCode()
	}

	static TestUserRoleGroup get(long userId, long roleGroupId) {
		criteriaFor(userId, roleGroupId).get()
	}

	static boolean exists(long userId, long roleGroupId) {
		criteriaFor(userId, roleGroupId).count()
	}

	private static DetachedCriteria criteriaFor(long userId, long roleGroupId) {
		TestUserRoleGroup.where {
			user == TestUser.load(userId) &&
			roleGroup == TestRoleGroup.load(roleGroupId)
		}
	}

	static TestUserRoleGroup create(TestUser user, TestRoleGroup roleGroup, boolean flush = false) {
		def instance = new TestUserRoleGroup(user: user, roleGroup: roleGroup)
		instance.save(flush: flush, insert: true)
		instance
	}

	static boolean remove(TestUser u, TestRoleGroup rg, boolean flush = false) {
		if (u == null || rg == null) return false

		int rowCount = TestUserRoleGroup.where { user == u && roleGroup == rg }.deleteAll()

		if (flush) { TestUserRoleGroup.withSession { it.flush() } }

		rowCount
	}

	static void removeAll(TestUser u, boolean flush = false) {
		if (u == null) return

		TestUserRoleGroup.where { user == u }.deleteAll()

		if (flush) { TestUserRoleGroup.withSession { it.flush() } }
	}

	static void removeAll(TestRoleGroup rg, boolean flush = false) {
		if (rg == null) return

		TestUserRoleGroup.where { roleGroup == rg }.deleteAll()

		if (flush) { TestUserRoleGroup.withSession { it.flush() } }
	}

	static constraints = {
		user validator: { TestUser u, TestUserRoleGroup ug ->
			if (ug.roleGroup == null || ug.roleGroup.id == null) return
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
