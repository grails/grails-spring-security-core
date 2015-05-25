package com.testapp

import org.apache.commons.lang.builder.HashCodeBuilder

class TestUserTestRole implements Serializable {

	private static final long serialVersionUID = 1

	TestUser testUser
	TestRole testRole

	boolean equals(other) {
		if (!(other instanceof TestUserTestRole)) {
			return false
		}

		other.testUser?.id == testUser?.id &&
			other.testRole?.id == testRole?.id
	}

	int hashCode() {
		def builder = new HashCodeBuilder()
		if (testUser) builder.append(testUser.id)
		if (testRole) builder.append(testRole.id)
		builder.toHashCode()
	}

	static TestUserTestRole get(long testUserId, long testRoleId) {
		TestUserTestRole.where {
			testUser == TestUser.load(testUserId) &&
			testRole == TestRole.load(testRoleId)
		}.get()
	}

	static TestUserTestRole create(TestUser testUser, TestRole testRole, boolean flush = false) {
		new TestUserTestRole(testUser: testUser, testRole: testRole).save(flush: flush, insert: true)
	}

	static boolean remove(TestUser u, TestRole r, boolean flush = false) {

		int rowCount = TestUserTestRole.where {
			testUser == TestUser.load(u.id) &&
			testRole == TestRole.load(r.id)
		}.deleteAll()

		rowCount > 0
	}

	static void removeAll(TestUser u) {
		TestUserTestRole.where {
			testUser == TestUser.load(u.id)
		}.deleteAll()
	}

	static void removeAll(TestRole r) {
		TestUserTestRole.where {
			testRole == TestRole.load(r.id)
		}.deleteAll()
	}

	static mapping = {
		id composite: ['testRole', 'testUser']
		version false
	}
}
