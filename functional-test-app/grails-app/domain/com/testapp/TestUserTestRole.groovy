package com.testapp

import grails.gorm.DetachedCriteria
import groovy.transform.ToString
import org.apache.commons.lang.builder.HashCodeBuilder

@ToString(cache=true, includeNames=true, includePackage=false)
class TestUserTestRole implements Serializable {
	private static final long serialVersionUID = 1

	TestUser testUser
	TestRole testRole

	@Override
	boolean equals(other) {
		if (other instanceof TestUserTestRole) {
			other.testUserId == testUser?.id && other.testRoleId == testRole?.id
		}
	}

	@Override
	int hashCode() {
		def builder = new HashCodeBuilder()
		if (testUser) builder.append(testUser.id)
		if (testRole) builder.append(testRole.id)
		builder.toHashCode()
	}

	static TestUserTestRole get(long testUserId, long testRoleId) {
		criteriaFor(testUserId, testRoleId).get()
	}

	static boolean exists(long testUserId, long testRoleId) {
		criteriaFor(testUserId, testRoleId).count()
	}

	private static DetachedCriteria criteriaFor(long testUserId, long testRoleId) {
		TestUserTestRole.where {
			testUser == TestUser.load(testUserId) &&
			testRole == TestRole.load(testRoleId)
		}
	}

	static TestUserTestRole create(TestUser testUser, TestRole testRole) {
		def instance = new TestUserTestRole(testUser: testUser, testRole: testRole)
		instance.save()
		instance
	}

	static boolean remove(TestUser u, TestRole r) {
		if (u != null && r != null) {
			TestUserTestRole.where { testUser == u && testRole == r }.deleteAll()
		}
	}

	static int removeAll(TestUser u) {
		u ? TestUserTestRole.where { testUser == u }.deleteAll() : 0
	}

	static void removeAll(TestRole r) {
		r ? TestUserTestRole.where { testRole == r }.deleteAll() : 0
	}

	static constraints = {
		testRole validator: { TestRole r, TestUserTestRole ur ->
			if (ur.testUser?.id) {
				TestUserTestRole.withNewSession {
					if (TestUserTestRole.exists(ur.testUser.id, r.id)) {
						return ['userRole.exists']
					}
				}
			}
		}
	}

	static mapping = {
		id composite: ['testUser', 'testRole']
		version false
	}
}
