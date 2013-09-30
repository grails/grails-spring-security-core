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
package grails.plugin.springsecurity

import org.codehaus.groovy.grails.commons.ConfigurationHolder as CH
import org.springframework.security.core.userdetails.UsernameNotFoundException

import test.TestRole
import test.TestUser
import test.TestUserRole

/**
 * Integration tests for GormUserDetailsService.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class GormUserDetailsServiceTests extends GroovyTestCase {

	private static final String ADMIN_ROLE_NAME = 'ROLE_ADMIN'
	private static final String SUPER_ADMIN_ROLE_NAME = 'ROLE_SUPERADMIN'

	private TestRole _adminRole
	private TestRole _superAdminRole

	def sessionFactory
	def userDetailsService

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#setUp()
	 */
	@Override
	protected void setUp() {
		super.setUp()
		CH.config = new ConfigObject()

		assertEquals 0, TestRole.count()
		_adminRole = new TestRole(auth: ADMIN_ROLE_NAME, description: 'admin').save()
		_superAdminRole = new TestRole(auth: SUPER_ADMIN_ROLE_NAME, description: 'super admin').save()
		assertEquals 2, TestRole.count()
	}

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#tearDown()
	 */
	@Override
	protected void tearDown() {
		super.tearDown()
		CH.config = null
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
		new TestUser(loginName: loginName, passwrrd: 'password', enabld: true).save()
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
		def user = new TestUser(loginName: loginName, passwrrd: password, enabld: enabled).save()
		assertEquals 1, TestUser.count()

		TestUserRole.create user, _adminRole, true
		TestUserRole.create user, _superAdminRole, true

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

	void testLoadUserByUsername_SkipRoles() {

		String loginName = 'loginName'
		String password = 'password123'
		boolean enabled = true

		assertEquals 0, TestUser.count()
		def user = new TestUser(loginName: loginName, passwrrd: password, enabld: enabled).save()
		assertEquals 1, TestUser.count()

		TestUserRole.create user, _adminRole
		TestUserRole.create user, _superAdminRole

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
