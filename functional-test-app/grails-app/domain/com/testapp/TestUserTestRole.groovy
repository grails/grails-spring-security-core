package com.testapp

import grails.gorm.DetachedCriteria
import groovy.transform.ToString

import org.apache.commons.lang.builder.HashCodeBuilder

@ToString(cache=true, includeNames=true, includePackage=false)
class TestUserTestRole implements Serializable {

	private static final long serialVersionUID = 1

	TestUser testUser
	TestRole testRole

	TestUserTestRole(TestUser u, TestRole r) {
		this()
		testUser = u
		testRole = r
	}

	@Override
	boolean equals(other) {
		if (!(other instanceof TestUserTestRole)) {
			return false
		}

		other.testUser?.id == testUser?.id && other.testRole?.id == testRole?.id
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

	static TestUserTestRole create(TestUser testUser, TestRole testRole, boolean flush = false) {
		def instance = new TestUserTestRole(testUser, testRole)
		instance.save(flush: flush, insert: true)
		instance
	}

	static boolean remove(TestUser u, TestRole r, boolean flush = false) {
		if (u == null || r == null) return false

//		int rowCount = TestUserTestRole.where { testUser == u && testRole == r }.deleteAll()
		TestUserTestRole.where { testUser == u && testRole == r }.list()*.delete()

		if (flush) { TestUserTestRole.withSession { it.flush() } }

//		rowCount
	}

	static void removeAll(TestUser u, boolean flush = false) {
		if (u == null) return

//		TestUserTestRole.where { testUser == u }.deleteAll()
		TestUserTestRole.where { testUser == u }.list()*.delete()

		if (flush) { TestUserTestRole.withSession { it.flush() } }
	}

	static void removeAll(TestRole r, boolean flush = false) {
		if (r == null) return

//		TestUserTestRole.where { testRole == r }.deleteAll()
		TestUserTestRole.where { testRole == r }.list()*.delete()

		if (flush) { TestUserTestRole.withSession { it.flush() } }
	}

	static constraints = {
		testRole validator: { TestRole r, TestUserTestRole ur ->
			if (ur.testUser == null || ur.testUser.id == null) return
			boolean existing = false
			TestUserTestRole.withNewSession {
				existing = TestUserTestRole.exists(ur.testUser.id, r.id)
			}
			if (existing) {
				return 'userRole.exists'
			}
		}
	}

	static mapping = {
		id composite: ['testUser', 'testRole']
		version false
	}
}
