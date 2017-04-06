package test

import grails.gorm.DetachedCriteria
import groovy.transform.ToString
import org.codehaus.groovy.util.HashCodeHelper

@ToString(cache=true, includeNames=true, includePackage=false)
class TestUserRoleGroup implements Serializable {

	private static final long serialVersionUID = 1

	TestUser user
	TestRoleGroup roleGroup

	@Override
	boolean equals(other) {
		if (other instanceof TestUserRoleGroup) {
			other.userId == user?.id && other.roleGroupId == roleGroup?.id
		}
	}

	@Override
	int hashCode() {
		int hashCode = HashCodeHelper.initHash()
		if (user) {
			hashCode = HashCodeHelper.updateHash(hashCode, user.id)
		}
		if (roleGroup) {
			hashCode = HashCodeHelper.updateHash(hashCode, roleGroup.id)
		}
		hashCode
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

	static TestUserRoleGroup create(TestUser user, TestRoleGroup roleGroup) {
		def instance = new TestUserRoleGroup(user: user, roleGroup: roleGroup)
		instance.save()
		instance
	}

	static boolean remove(TestUser u, TestRoleGroup rg) {
		if (u && rg) {
			TestUserRoleGroup.where { user == u && roleGroup == rg }.deleteAll()
		}
	}

	static int removeAll(TestUser u) {
		u ? TestUserRoleGroup.where { user == u }.deleteAll() : 0
	}

	static int removeAll(TestRoleGroup rg) {
		rg ? TestUserRoleGroup.where { roleGroup == rg }.deleteAll() : 0
	}

	static constraints = {
		user validator: { TestUser u, TestUserRoleGroup ug ->
			if (ug.roleGroup?.id ) {
				TestUserRoleGroup.withNewSession {
					if (TestUserRoleGroup.exists(u.id, ug.roleGroup.id)) {
						return ['userGroup.exists']
					}
				}
			}
		}
	}

	static mapping = {
		id composite: ['roleGroup', 'user']
		version false
	}
}
