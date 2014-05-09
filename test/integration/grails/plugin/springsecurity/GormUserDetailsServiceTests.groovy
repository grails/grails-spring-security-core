/* Copyright 2006-2014 SpringSource.
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

import org.springframework.security.core.userdetails.UsernameNotFoundException

import test.TestRole
import test.TestRoleGroup
import test.TestRoleGroupRoles
import test.TestUser
import test.TestUserRole
import test.TestUserRoleGroup

import grails.test.mixin.integration.IntegrationTestMixin
import grails.test.mixin.*
import org.junit.*
import static org.junit.Assert.*

/**
 * Integration tests for GormUserDetailsService.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
@TestMixin(IntegrationTestMixin)
class GormUserDetailsServiceTests  {

	private static final String ADMIN_ROLE_NAME = 'ROLE_ADMIN'
	private static final String SUPER_ADMIN_ROLE_NAME = 'ROLE_SUPERADMIN'

	private TestRole adminRole
	private TestRole superAdminRole

	private securityConfigGroupPropertyNames = ['useRoleGroups', 'authority.className', 'authority.nameField',
	                                            'authority.groupAuthorityNameField', 'userLookup.authoritiesPropertyName']
	private securityConfigGroupPropertyValues = securityConfigGroupPropertyNames.collectEntries { String name ->
		[(name): ReflectionUtils.getConfigProperty(name)]
	}

	def sessionFactory
	def userDetailsService

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#setUp()
	 */
	@Before
	void setUp() {
		org.codehaus.groovy.grails.commons.ConfigurationHolder.config = new ConfigObject()
		assertEquals 0, TestRole.count()
		adminRole = new TestRole(auth: ADMIN_ROLE_NAME, description: 'admin').save(failOnError: true)
		superAdminRole = new TestRole(auth: SUPER_ADMIN_ROLE_NAME, description: 'super admin').save(failOnError: true)
		assertEquals 2, TestRole.count()
	}

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#tearDown()
	 */
	@After
	void tearDown() {
		org.codehaus.groovy.grails.commons.ConfigurationHolder.config = null
		securityConfigGroupPropertyValues.each { key, value ->
			ReflectionUtils.setConfigProperty key, value
		}
	}

	void testLoadUserByUsername_NotFound() {
		String message = shouldFail(UsernameNotFoundException) {
			userDetailsService.loadUserByUsername 'not_a_user'
		}

		assertTrue message.contains('not found')
	}

	void testLoadUserByUsername_NoRoles() {

		String loginName = 'loginName'

		assertEquals 0, TestUser.count()
		new TestUser(loginName: loginName, passwrrd: 'password', enabld: true).save(failOnError: true)
		assertEquals 1, TestUser.count()

		def details = userDetailsService.loadUserByUsername(loginName)
		assertEquals 1, details.authorities.size()
		assertEquals 'ROLE_NO_ROLES', details.authorities.iterator().next().authority
	}

	void testLoadUserByUsername() {

		String loginName = 'loginName'
		String password = 'password123'
		boolean enabled = true

		assertEquals 0, TestUser.count()
		def user = new TestUser(loginName: loginName, passwrrd: password, enabld: enabled).save(failOnError: true)
		assertEquals 1, TestUser.count()

		TestUserRole.create user, adminRole
		TestUserRole.create user, superAdminRole, true
		assertEquals 2, TestUserRole.count()

		def details = userDetailsService.loadUserByUsername(loginName)
		assertNotNull details

		assertEquals password, details.password
		assertEquals loginName, details.username
		assertEquals enabled, details.enabled
		assertEquals enabled, details.accountNonExpired
		assertEquals enabled, details.accountNonLocked
		assertEquals enabled, details.credentialsNonExpired
		assertEquals([ADMIN_ROLE_NAME, SUPER_ADMIN_ROLE_NAME], details.authorities*.authority.sort())
	}

	void testLoadUserByUsername_Groups() {
		//Change the config to use authority groups
		ReflectionUtils.setConfigProperty 'useRoleGroups', true
		ReflectionUtils.setConfigProperty 'authority.className', 'test.TestRoleGroup'
		ReflectionUtils.setConfigProperty 'authority.nameField', 'auth'
		ReflectionUtils.setConfigProperty 'authority.groupAuthorityNameField', 'roles'
		ReflectionUtils.setConfigProperty 'userLookup.authoritiesPropertyName', 'groups'

		String loginName = 'loginName'
		String password = 'password123'
		boolean enabled = true

		assertEquals 0, TestUser.count()
		def user = new TestUser(loginName: loginName, passwrrd: password, enabld: enabled).save(failOnError: true)
		assertEquals 1, TestUser.count()

		assertEquals 0, TestRoleGroup.count()
		def roleGroup = new TestRoleGroup(name: 'testRoleGroup1').save(failOnError: true)
		assertEquals 1, TestRoleGroup.count()

		TestRoleGroupRoles.create roleGroup, adminRole
		TestRoleGroupRoles.create roleGroup, superAdminRole, true
		assertEquals 2, TestRoleGroupRoles.count()

		assertEquals 0, TestUserRoleGroup.count()
		TestUserRoleGroup.create user, roleGroup, true
		assertEquals 1, TestUserRoleGroup.count()

		def details = userDetailsService.loadUserByUsername(loginName)
		assertNotNull details

		assertEquals([ADMIN_ROLE_NAME, SUPER_ADMIN_ROLE_NAME], details.authorities*.authority.sort())
	}

	void testLoadUserByUsername_SkipRoles() {

		String loginName = 'loginName'
		String password = 'password123'
		boolean enabled = true

		assertEquals 0, TestUser.count()
		def user = new TestUser(loginName: loginName, passwrrd: password, enabld: enabled).save(failOnError: true)
		assertEquals 1, TestUser.count()

		TestUserRole.create user, adminRole
		TestUserRole.create user, superAdminRole, true

		def details = userDetailsService.loadUserByUsername(loginName, false)
		assertNotNull details

		assertEquals password, details.password
		assertEquals loginName, details.username
		assertEquals enabled, details.enabled
		assertEquals enabled, details.accountNonExpired
		assertEquals enabled, details.accountNonLocked
		assertEquals enabled, details.credentialsNonExpired
		assertEquals 0, details.authorities.size()
	}
}
