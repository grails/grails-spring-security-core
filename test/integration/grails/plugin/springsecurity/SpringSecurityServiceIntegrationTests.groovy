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

import test.TestRequestmap
import test.TestRole

/**
 * Integration tests for SpringSecurityService.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class SpringSecurityServiceIntegrationTests extends GroovyTestCase {

	def sessionFactory
	SpringSecurityService springSecurityService
	private oldConfig

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#setUp()
	 */
	@Override
	protected void setUp() {
		super.setUp()

		oldConfig = SpringSecurityUtils.securityConfig

		def requestMapConfig = SpringSecurityUtils.securityConfig.requestMap
		requestMapConfig.className = TestRequestmap.name
		requestMapConfig.urlField = 'urlPattern'
		requestMapConfig.configAttributeField = 'rolePattern'
		SpringSecurityUtils.securityConfig.securityConfigType = SecurityConfigType.Requestmap

		createTestRequestmaps()
	}

	void testUpdateRole_Invalid() {

		String description = 'description'
		String authority = 'ROLE_ADMIN'
		def role = new TestRole(description: description, auth: authority).save(flush: true)

		sessionFactory.currentSession.clear()

		role = TestRole.list()[0]
		assertEquals description, role.description
		assertEquals authority, role.auth

		String newDescription = 'new description'
		String newAuthority = ''
		assertFalse springSecurityService.updateRole(role, [description: newDescription, auth: newAuthority])

		def requestmaps = TestRequestmap.list()
		assertEquals 'ROLE_USER', requestmaps[0].rolePattern
		assertEquals 'ROLE_ADMIN', requestmaps[1].rolePattern
		assertEquals 'ROLE_ADMIN,ROLE_FOO', requestmaps[2].rolePattern
		assertEquals 'ROLE_USER,ROLE_ADMIN,ROLE_FOO', requestmaps[3].rolePattern
		assertEquals 'ROLE_ADMIN,ROLE_FOO', requestmaps[4].rolePattern
	}

	void testUpdateRole() {

		String description = 'description'
		String authority = 'ROLE_ADMIN'
		def role = new TestRole(description: description, auth: authority).save(flush: true)

		sessionFactory.currentSession.clear()

		role = TestRole.list()[0]
		assertEquals description, role.description
		assertEquals authority, role.auth

		String newDescription = 'new description'
		String newAuthority = 'ROLE_SUPERADMIN'
		assertTrue springSecurityService.updateRole(role, [description: newDescription, auth: newAuthority])
		assertEquals newDescription, role.description
		assertEquals newAuthority, role.auth

		def requestmaps = TestRequestmap.list()
		assertEquals 'ROLE_USER', requestmaps[0].rolePattern
		assertEquals 'ROLE_SUPERADMIN', requestmaps[1].rolePattern
		assertEquals 'ROLE_SUPERADMIN,ROLE_FOO', requestmaps[2].rolePattern
		assertEquals 'ROLE_USER,ROLE_SUPERADMIN,ROLE_FOO', requestmaps[3].rolePattern
		assertEquals 'ROLE_SUPERADMIN,ROLE_FOO', requestmaps[4].rolePattern
	}

	void testDeleteRole() {

		def requestmaps = TestRequestmap.list()
		def role = new TestRole(auth: 'ROLE_ADMIN', description: 'admin').save(flush: true)

		springSecurityService.deleteRole role

		sessionFactory.currentSession.clear()

		assertEquals 4, TestRequestmap.count()

		assertEquals 'ROLE_USER', requestmaps[0].rolePattern
		assertNull 'Should have been deleted', TestRequestmap.findByRolePattern('ROLE_ADMIN')
		assertEquals 'ROLE_FOO', requestmaps[2].rolePattern
		assertEquals 'ROLE_USER,ROLE_FOO', requestmaps[3].rolePattern
		assertEquals 'ROLE_FOO', requestmaps[4].rolePattern

		assertNull TestRole.findByAuth('ROLE_ADMIN')
	}

	private void createTestRequestmaps() {
		new TestRequestmap(urlPattern: '/user/**', rolePattern: 'ROLE_USER').save()
		new TestRequestmap(urlPattern: '/admin/role/**', rolePattern: 'ROLE_ADMIN').save()
		new TestRequestmap(urlPattern: '/admin/person/**', rolePattern: 'ROLE_ADMIN,ROLE_FOO').save()
		new TestRequestmap(urlPattern: '/admin/foo/**', rolePattern: 'ROLE_USER,ROLE_ADMIN,ROLE_FOO').save()
		new TestRequestmap(urlPattern: '/admin/super/**', rolePattern: 'ROLE_ADMIN,ROLE_FOO').save()
		sessionFactory.currentSession.flush()
		assertEquals 5, TestRequestmap.count()
	}

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#tearDown()
	 */
	@Override
	protected void tearDown() {
		super.tearDown()
		SpringSecurityUtils.securityConfig = oldConfig
	}
}
