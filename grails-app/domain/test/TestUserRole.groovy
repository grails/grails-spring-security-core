/* Copyright 2006-2013 SpringSource.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package test

import org.apache.commons.lang.builder.HashCodeBuilder

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class TestUserRole implements Serializable {

	private static final long serialVersionUID = 1

	TestUser user
	TestRole role

	boolean equals(other) {
		if (!(other instanceof TestUserRole)) {
			return false
		}

		other.user?.id == user?.id && other.role?.id == role?.id
	}

	int hashCode() {
		def builder = new HashCodeBuilder()
		if (user) builder.append(user.id)
		if (role) builder.append(role.id)
		builder.toHashCode()
	}

	static TestUserRole get(long userId, long roleId) {
		TestUserRole.where {
			user == TestUser.load(userId) &&
			role == TestRole.load(roleId)
		}.get()
	}

	static boolean exists(long userId, long roleId) {
		TestUserRole.where {
			user == TestUser.load(userId) &&
			role == TestRole.load(roleId)
		}.count() > 0
	}

	static TestUserRole create(TestUser user, TestRole role, boolean flush = false) {
		def instance = new TestUserRole(user: user, role: role)
		instance.save(flush: flush, insert: true)
		instance
	}

	static boolean remove(TestUser u, TestRole r, boolean flush = false) {
		int rowCount = TestUserRole.where {
			user == TestUser.load(u.id) &&
			role == TestRole.load(r.id)
		}.deleteAll()

		if (flush) { TestUserRole.withSession { it.flush() } }

		rowCount > 0
	}

	static void removeAll(TestUser u, boolean flush = false) {
		TestUserRole.where {
			user == TestUser.load(u.id)
		}.deleteAll()

		if (flush) { TestUserRole.withSession { it.flush() } }
	}

	static void removeAll(TestRole r, boolean flush = false) {
		TestUserRole.where {
			role == TestRole.load(r.id)
		}.deleteAll()

		if (flush) { TestUserRole.withSession { it.flush() } }
	}

	static constraints = {
		role validator: { TestRole r, TestUserRole ur ->
			if (ur.role == null) return
			boolean existing = false
			TestUserRole.withNewSession {
				existing = TestUserRole.exists(ur.user.id, r.id)
			}
			if (existing) {
				return 'userRole.exists'
			}
		}
	}

	static mapping = {
		id composite: ['role', 'user']
		version false
	}
}
