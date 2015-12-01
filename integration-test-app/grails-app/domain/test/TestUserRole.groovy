/* Copyright 2006-2015 the original author or authors.
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

import grails.gorm.DetachedCriteria
import groovy.transform.ToString

import org.apache.commons.lang.builder.HashCodeBuilder

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
@ToString(cache=true, includeNames=true, includePackage=false)
class TestUserRole implements Serializable {

	private static final long serialVersionUID = 1

	TestUser user
	TestRole role

	TestUserRole(TestUser u, TestRole r) {
		this()
		user = u
		role = r
	}

	@Override
	boolean equals(other) {
		if (!(other instanceof TestUserRole)) {
			return false
		}

		other.user?.id == user?.id && other.role?.id == role?.id
	}

	@Override
	int hashCode() {
		def builder = new HashCodeBuilder()
		if (user) builder.append(user.id)
		if (role) builder.append(role.id)
		builder.toHashCode()
	}

	static TestUserRole get(long userId, long roleId) {
		criteriaFor(userId, roleId).get()
	}

	static boolean exists(long userId, long roleId) {
		criteriaFor(userId, roleId).count()
	}

	private static DetachedCriteria criteriaFor(long userId, long roleId) {
		TestUserRole.where {
			user == TestUser.load(userId) &&
			role == TestRole.load(roleId)
		}
	}

	static TestUserRole create(TestUser user, TestRole role, boolean flush = false) {
		def instance = new TestUserRole(user, role)
		instance.save(flush: flush, insert: true)
		instance
	}

	static boolean remove(TestUser u, TestRole r, boolean flush = false) {
		if (u == null || r == null) return false

		int rowCount = TestUserRole.where { user == u && role == r }.deleteAll()

		if (flush) { TestUserRole.withSession { it.flush() } }

		rowCount
	}

	static void removeAll(TestUser u, boolean flush = false) {
		if (u == null) return

		TestUserRole.where { user == u }.deleteAll()

		if (flush) { TestUserRole.withSession { it.flush() } }
	}

	static void removeAll(TestRole r, boolean flush = false) {
		if (r == null) return

		TestUserRole.where { role == r }.deleteAll()

		if (flush) { TestUserRole.withSession { it.flush() } }
	}

	static constraints = {
		role validator: { TestRole r, TestUserRole ur ->
			if (ur.user == null || ur.user.id == null) return
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
		id composite: ['user', 'role']
		version false
	}
}
