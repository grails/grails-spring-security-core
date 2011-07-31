/* Copyright 2006-2010 the original author or authors.
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
		if (!instance) {
			return false
		}

		instance.delete(flush: flush)
		true
	}

	static void removeAll(TestUser user) {
		executeUpdate "DELETE FROM TestUserRole WHERE user=:user", [user: user]
	}

	static void removeAll(TestRole role) {
		executeUpdate 'DELETE FROM TestUserRole WHERE role=:role', [role: role]
	}

	static mapping = {
		id composite: ['role', 'user']
		version false
	}
}
