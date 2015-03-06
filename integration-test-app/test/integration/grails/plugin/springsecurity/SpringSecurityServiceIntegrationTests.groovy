/* Copyright 2006-2015 SpringSource.
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

import grails.test.mixin.TestMixin
import grails.test.mixin.integration.IntegrationTestMixin

import org.junit.After
import org.junit.Before

import test.TestRequestmap
import test.TestRole

/**
 * Integration tests for SpringSecurityService.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
@TestMixin(IntegrationTestMixin)
class SpringSecurityServiceIntegrationTests {

	def sessionFactory
	SpringSecurityService springSecurityService
	private oldConfig

	@Before
	void setUp() {
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
		assert description == role.description
		assert authority == role.auth

		String newDescription = 'new description'
		String newAuthority = ''
		assert !springSecurityService.updateRole(role, [description: newDescription, auth: newAuthority])

		def requestmaps = TestRequestmap.list()
		assert 'ROLE_USER' == requestmaps[0].rolePattern
		assert 'ROLE_ADMIN' == requestmaps[1].rolePattern
		assert 'ROLE_ADMIN,ROLE_FOO' == requestmaps[2].rolePattern
		assert 'ROLE_USER,ROLE_ADMIN,ROLE_FOO' == requestmaps[3].rolePattern
		assert 'ROLE_ADMIN,ROLE_FOO' == requestmaps[4].rolePattern
	}

	void testUpdateRole() {

		String description = 'description'
		String authority = 'ROLE_ADMIN'
		def role = new TestRole(description: description, auth: authority).save(flush: true)

		sessionFactory.currentSession.clear()

		role = TestRole.list()[0]
		assert description == role.description
		assert authority == role.auth

		String newDescription = 'new description'
		String newAuthority = 'ROLE_SUPERADMIN'
		assert springSecurityService.updateRole(role, [description: newDescription, auth: newAuthority])
		assert newDescription == role.description
		assert newAuthority == role.auth

		def requestmaps = TestRequestmap.list()
		assert 'ROLE_USER' == requestmaps[0].rolePattern
		assert 'ROLE_SUPERADMIN' == requestmaps[1].rolePattern
		assert 'ROLE_SUPERADMIN,ROLE_FOO' == requestmaps[2].rolePattern
		assert 'ROLE_USER,ROLE_SUPERADMIN,ROLE_FOO' == requestmaps[3].rolePattern
		assert 'ROLE_SUPERADMIN,ROLE_FOO' == requestmaps[4].rolePattern
	}

	void testDeleteRole() {

		def requestmaps = TestRequestmap.list()
		def role = new TestRole(auth: 'ROLE_ADMIN', description: 'admin').save(flush: true)

		springSecurityService.deleteRole role

		sessionFactory.currentSession.clear()

		assert 4 == TestRequestmap.count()

		assert 'ROLE_USER' == requestmaps[0].rolePattern
		assert !TestRequestmap.findByRolePattern('ROLE_ADMIN'), 'Should have been deleted'
		assert 'ROLE_FOO' == requestmaps[2].rolePattern
		assert 'ROLE_USER,ROLE_FOO' == requestmaps[3].rolePattern
		assert 'ROLE_FOO' == requestmaps[4].rolePattern

		assert !TestRole.findByAuth('ROLE_ADMIN')
	}

	private void createTestRequestmaps() {
		new TestRequestmap(urlPattern: '/user/**', rolePattern: 'ROLE_USER').save()
		new TestRequestmap(urlPattern: '/admin/role/**', rolePattern: 'ROLE_ADMIN').save()
		new TestRequestmap(urlPattern: '/admin/person/**', rolePattern: 'ROLE_ADMIN,ROLE_FOO').save()
		new TestRequestmap(urlPattern: '/admin/foo/**', rolePattern: 'ROLE_USER,ROLE_ADMIN,ROLE_FOO').save()
		new TestRequestmap(urlPattern: '/admin/super/**', rolePattern: 'ROLE_ADMIN,ROLE_FOO').save()
		sessionFactory.currentSession.flush()
		assert 5 == TestRequestmap.count()
	}

	@After
	void tearDown() {
		SpringSecurityUtils.securityConfig = oldConfig
	}
}
