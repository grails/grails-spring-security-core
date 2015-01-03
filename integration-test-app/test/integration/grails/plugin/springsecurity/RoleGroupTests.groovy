/* Copyright 2014-2015 SpringSource.
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
package grails.plugin.springsecurity

import org.springframework.validation.Errors

import test.TestRole
import test.TestRoleGroup
import test.TestRoleGroupRoles
import test.TestUser
import test.TestUserRoleGroup

/**
 * Integration tests for the RoleGroup and RoleGroupRoles domain classes.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class RoleGroupTests extends GroovyTestCase {

	def messageSource

	void testRoleGroup_GetRoles() {

		TestRoleGroup rg1 = save(new TestRoleGroup(name: 'rg1'))
		TestRoleGroup rg2 = save(new TestRoleGroup(name: 'rg2'))

		5.times { i ->
			def r = save(new TestRole(auth: "r$i", description: "r$i"))
			TestRoleGroupRoles.create rg1, r
			if (i > 2) {
				TestRoleGroupRoles.create rg2, r
			}
		}

		flushAndClear()

		rg1 = TestRoleGroup.get(rg1.id)
		rg2 = TestRoleGroup.get(rg2.id)

		assert ['r0', 'r1', 'r2', 'r3', 'r4'] == rg1.roles*.auth.sort()
		assert ['r3', 'r4'] == rg2.roles*.auth.sort()
	}

	void testUserRoleGroup_EqualsAndHashCode() {

		TestRoleGroup rg1 = save(new TestRoleGroup(name: 'rg1'))
		TestRoleGroup rg2 = save(new TestRoleGroup(name: 'rg2'))
		TestUser u1 = save(new TestUser(loginName: 'u1', passwrrd: 'u1'))
		TestUser u2 = save(new TestUser(loginName: 'u2', passwrrd: 'u2'))

		TestUserRoleGroup urg1 = new TestUserRoleGroup(user: u1, roleGroup: rg1)
		TestUserRoleGroup urg2 = new TestUserRoleGroup(user: u1, roleGroup: rg1)
		assert urg1 == urg2
		assert urg1.hashCode() == urg2.hashCode()

		urg1.user = u2
		assert urg1 != urg2
		assert urg1.hashCode() != urg2.hashCode()

		urg1.user = u1
		urg1.roleGroup = rg2
		assert urg1 != urg2
		assert urg1.hashCode() != urg2.hashCode()

		urg1.user = u2
		urg1.roleGroup = rg1
		assert urg1 != urg2
		assert urg1.hashCode() != urg2.hashCode()

		urg1.roleGroup = rg2
		assert urg1 != urg2
		assert urg1.hashCode() != urg2.hashCode()
	}

	void testRoleGroupRole_EqualsAndHashCode() {

		TestRoleGroup rg1 = save(new TestRoleGroup(name: 'rg1'))
		TestRoleGroup rg2 = save(new TestRoleGroup(name: 'rg2'))
		TestRole r1 = save(new TestRole(auth: 'r1', description: 'r1'))
		TestRole r2 = save(new TestRole(auth: 'r2', description: 'r2'))

		TestRoleGroupRoles rgr1 = new TestRoleGroupRoles(role: r1, roleGroup: rg1)
		TestRoleGroupRoles rgr2 = new TestRoleGroupRoles(role: r1, roleGroup: rg1)
		assert rgr1 == rgr2
		assert rgr1.hashCode() == rgr2.hashCode()

		rgr1.role = r2
		assert rgr1 != rgr2
		assert rgr1.hashCode() != rgr2.hashCode()

		rgr1.role = r1
		rgr1.roleGroup = rg2
		assert rgr1 != rgr2
		assert rgr1.hashCode() != rgr2.hashCode()

		rgr1.role = r2
		rgr1.roleGroup = rg1
		assert rgr1 != rgr2
		assert rgr1.hashCode() != rgr2.hashCode()

		rgr1.roleGroup = rg2
		assert rgr1 != rgr2
		assert rgr1.hashCode() != rgr2.hashCode()
	}

	void testUserRoleGroup_create() {

		TestRoleGroup rg1 = save(new TestRoleGroup(name: 'rg1'))
		TestUser u1 = save(new TestUser(loginName: 'u1', passwrrd: 'u1'))

		def instance = TestUserRoleGroup.create(null, null)
		assert instance
		assert instance.hasErrors()
		assert 2 == instance.errors.errorCount
		def fieldError = instance.errors.getFieldError('user')
		assert fieldError
		assert 'Property [user] of class [class test.TestUserRoleGroup] cannot be null' == getMessage(fieldError)
		fieldError = instance.errors.getFieldError('roleGroup')
		assert fieldError
		assert 'Property [roleGroup] of class [class test.TestUserRoleGroup] cannot be null' == getMessage(fieldError)

		instance = TestUserRoleGroup.create(null, rg1)
		assert instance
		assert instance.hasErrors()
		assert 1 == instance.errors.errorCount
		fieldError = instance.errors.getFieldError('user')
		assert fieldError
		assert 'Property [user] of class [class test.TestUserRoleGroup] cannot be null' == getMessage(fieldError)

		instance = TestUserRoleGroup.create(u1, null)
		assert instance
		assert instance.hasErrors()
		assert 1 == instance.errors.errorCount
		fieldError = instance.errors.getFieldError('roleGroup')
		assert fieldError
		assert 'Property [roleGroup] of class [class test.TestUserRoleGroup] cannot be null' == getMessage(fieldError)

		instance = TestUserRoleGroup.create(u1, rg1)
		assert instance
		assert !instance.hasErrors()

		flushAndClear()

		instance = TestUserRoleGroup.create(u1, rg1)
		assert instance
		assert instance.hasErrors()
		assert 1 == instance.errors.errorCount
		fieldError = instance.errors.getFieldError('user')
		assert fieldError
		assert 'userGroup.exists' == fieldError.code
	}

	void testRoleGroupRole_create() {
		TestRoleGroup rg1 = save(new TestRoleGroup(name: 'rg1'))
		TestRole r1 = save(new TestRole(auth: 'r1', description: 'r1'))

		def instance = TestRoleGroupRoles.create(null, null)
		assert instance
		assert instance.hasErrors()
		assert 2 == instance.errors.errorCount
		def fieldError = instance.errors.getFieldError('role')
		assert fieldError
		assert 'Property [role] of class [class test.TestRoleGroupRoles] cannot be null' == getMessage(fieldError)
		fieldError = instance.errors.getFieldError('roleGroup')
		assert fieldError
		assert 'Property [roleGroup] of class [class test.TestRoleGroupRoles] cannot be null' == getMessage(fieldError)

		instance = TestRoleGroupRoles.create(rg1, null)
		assert instance
		assert instance.hasErrors()
		assert 1 == instance.errors.errorCount
		fieldError = instance.errors.getFieldError('role')
		assert fieldError
		assert 'Property [role] of class [class test.TestRoleGroupRoles] cannot be null' == getMessage(fieldError)

		instance = TestRoleGroupRoles.create(null, r1)
		assert instance
		assert instance.hasErrors()
		assert 1 == instance.errors.errorCount
		fieldError = instance.errors.getFieldError('roleGroup')
		assert fieldError
		assert 'Property [roleGroup] of class [class test.TestRoleGroupRoles] cannot be null' == getMessage(fieldError)

		instance = TestRoleGroupRoles.create(rg1, r1)
		assert instance
		assert !instance.hasErrors()

		flushAndClear()

		instance = TestRoleGroupRoles.create(rg1, r1)
		assert instance
		assert instance.hasErrors()
		assert 1 == instance.errors.errorCount
		fieldError = instance.errors.getFieldError('role')
		assert fieldError
		assert 'roleGroup.exists' == fieldError.code
	}

	void testUserRoleGroup_get() {
		TestRoleGroup rg1 = save(new TestRoleGroup(name: 'rg1'))
		TestUser u1 = save(new TestUser(loginName: 'u1', passwrrd: 'u1'))

		assert !TestUserRoleGroup.get(u1.id, rg1.id)

		TestUserRoleGroup.create u1, rg1
		flushAndClear()

		assert TestUserRoleGroup.get(u1.id, rg1.id)
	}

	void testRoleGroupRole_get() {
		TestRoleGroup rg1 = save(new TestRoleGroup(name: 'rg1'))
		TestRole r1 = save(new TestRole(auth: 'r1', description: 'r1'))

		assert !TestRoleGroupRoles.get(rg1.id, r1.id)

		TestRoleGroupRoles.create rg1, r1
		flushAndClear()

		assert TestRoleGroupRoles.get(rg1.id, r1.id)
	}

	void testUserRoleGroup_exists() {
		TestRoleGroup rg1 = save(new TestRoleGroup(name: 'rg1'))
		TestUser u1 = save(new TestUser(loginName: 'u1', passwrrd: 'u1'))

		assert !TestUserRoleGroup.exists(u1.id, rg1.id)

		TestUserRoleGroup.create u1, rg1
		flushAndClear()

		assert TestUserRoleGroup.exists(u1.id, rg1.id)
	}

	void testRoleGroupRole_exists() {
		TestRoleGroup rg1 = save(new TestRoleGroup(name: 'rg1'))
		TestRole r1 = save(new TestRole(auth: 'r1', description: 'r1'))

		assert !TestRoleGroupRoles.exists(rg1.id, r1.id)

		TestRoleGroupRoles.create rg1, r1
		flushAndClear()

		assert TestRoleGroupRoles.exists(rg1.id, r1.id)
	}

	void testUserRoleGroup_remove() {
		TestRoleGroup rg1 = save(new TestRoleGroup(name: 'rg1'))
		TestUser u1 = save(new TestUser(loginName: 'u1', passwrrd: 'u1'))

		assert !TestUserRoleGroup.remove(u1, rg1)

		TestUserRoleGroup.create u1, rg1
		flushAndClear()

		assert TestUserRoleGroup.remove(u1, rg1)
	}

	void testRoleGroupRole_remove() {
		TestRoleGroup rg1 = save(new TestRoleGroup(name: 'rg1'))
		TestRole r1 = save(new TestRole(auth: 'r1', description: 'r1'))

		assert !TestRoleGroupRoles.remove(rg1, r1)

		TestRoleGroupRoles.create rg1, r1
		flushAndClear()

		assert TestRoleGroupRoles.remove(rg1, r1)
	}

	void testUserRoleGroup_removeAllByRoleGroup() {
		TestUser u1 = save(new TestUser(loginName: 'u1', passwrrd: 'u1'))
		TestUser u2 = save(new TestUser(loginName: 'u2', passwrrd: 'u2'))
		TestRoleGroup rg1 = save(new TestRoleGroup(name: 'rg1'))
		TestRoleGroup rg2 = save(new TestRoleGroup(name: 'rg2'))

		TestUserRoleGroup.create u1, rg1
		TestUserRoleGroup.create u2, rg1
		TestUserRoleGroup.create u1, rg2
		flushAndClear()

		assert 3 == TestUserRoleGroup.count()

		TestUserRoleGroup.removeAll rg1
		flushAndClear()

		assert 1 == TestUserRoleGroup.count()
	}

	void testRoleGroupRole_removeAllByRoleGroup() {
		TestRole r1 = save(new TestRole(auth: 'r1', description: 'r1'))
		TestRole r2 = save(new TestRole(auth: 'r2', description: 'r2'))
		TestRoleGroup rg1 = save(new TestRoleGroup(name: 'rg1'))
		TestRoleGroup rg2 = save(new TestRoleGroup(name: 'rg2'))

		TestRoleGroupRoles.create rg1, r1
		TestRoleGroupRoles.create rg1, r2
		TestRoleGroupRoles.create rg2, r1
		flushAndClear()

		assert 3 == TestRoleGroupRoles.count()

		TestRoleGroupRoles.removeAll rg1
		flushAndClear()

		assert 1 == TestRoleGroupRoles.count()
	}

	void testUserRoleGroup_removeAllByUser() {
		TestUser u1 = save(new TestUser(loginName: 'u1', passwrrd: 'u1'))
		TestUser u2 = save(new TestUser(loginName: 'u2', passwrrd: 'u2'))
		TestRoleGroup rg1 = save(new TestRoleGroup(name: 'rg1'))
		TestRoleGroup rg2 = save(new TestRoleGroup(name: 'rg2'))

		TestUserRoleGroup.create u1, rg1
		TestUserRoleGroup.create u2, rg1
		TestUserRoleGroup.create u1, rg2
		flushAndClear()

		assert 3 == TestUserRoleGroup.count()

		TestUserRoleGroup.removeAll u2
		flushAndClear()

		assert 2 == TestUserRoleGroup.count()
	}

	void testRoleGroupRole_removeAllByRole() {
		TestRole r1 = save(new TestRole(auth: 'r1', description: 'r1'))
		TestRole r2 = save(new TestRole(auth: 'r2', description: 'r2'))
		TestRoleGroup rg1 = save(new TestRoleGroup(name: 'rg1'))
		TestRoleGroup rg2 = save(new TestRoleGroup(name: 'rg2'))

		TestRoleGroupRoles.create rg1, r1
		TestRoleGroupRoles.create rg1, r2
		TestRoleGroupRoles.create rg2, r1
		flushAndClear()

		assert 3 == TestRoleGroupRoles.count()

		TestRoleGroupRoles.removeAll r2
		flushAndClear()

		assert 2 == TestRoleGroupRoles.count()
	}

	private save(o) {
		o.save(failOnError: true)
	}

	private void flushAndClear() {
		TestRoleGroup.withSession { session ->
			session.flush()
			session.clear()
		}
	}

	private String getMessage(fieldError) {
		messageSource.getMessage(fieldError, Locale.default)
	}
}
