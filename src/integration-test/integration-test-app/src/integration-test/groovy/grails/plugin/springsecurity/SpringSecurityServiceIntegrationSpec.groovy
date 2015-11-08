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
package grails.plugin.springsecurity

import test.TestRequestmap
import test.TestRole

/**
 * Integration tests for SpringSecurityService.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class SpringSecurityServiceIntegrationSpec extends AbstractIntegrationSpec {

	private static final String ROLE_ADMIN_DESCRIPTION = 'description'
	private static final String ROLE_ADMIN = 'ROLE_ADMIN'

	private oldConfig
	private TestRole role

	SpringSecurityService springSecurityService
	def servletContext

	void setup() {

		oldConfig = SpringSecurityUtils.securityConfig

		def requestMapConfig = SpringSecurityUtils.securityConfig.requestMap
		requestMapConfig.className = TestRequestmap.name
		requestMapConfig.urlField = 'urlPattern'
		requestMapConfig.configAttributeField = 'rolePattern'
		SpringSecurityUtils.securityConfig.securityConfigType = SecurityConfigType.Requestmap

		createTestRequestmaps()

		role = save(new TestRole(ROLE_ADMIN, ROLE_ADMIN_DESCRIPTION))
		flushAndClear()
	}

	void 'update role when invalid'() {

		when:
		TestRole role = TestRole.list()[0]

		then:
		ROLE_ADMIN_DESCRIPTION == role.description
		ROLE_ADMIN == role.auth

		when:
		String newDescription = 'new description'
		String newAuthority = ''
		boolean success = springSecurityService.updateRole(role, [description: newDescription, auth: newAuthority])

		then:
		!success

		when:
		def requestmaps = TestRequestmap.list()

		then:
		'ROLE_USER'                     == requestmaps[0].rolePattern
		'ROLE_ADMIN'                    == requestmaps[1].rolePattern
		'ROLE_ADMIN,ROLE_FOO'           == requestmaps[2].rolePattern
		'ROLE_USER,ROLE_ADMIN,ROLE_FOO' == requestmaps[3].rolePattern
		'ROLE_ADMIN,ROLE_FOO'           == requestmaps[4].rolePattern
	}

	void 'update role'() {

		when:
		TestRole role = TestRole.list()[0]

		then:
		ROLE_ADMIN_DESCRIPTION == role.description
		ROLE_ADMIN == role.auth

		when:
		String newDescription = 'new description'
		String newAuthority = 'ROLE_SUPERADMIN'

		boolean success = springSecurityService.updateRole(role, [description: newDescription, auth: newAuthority])

		then:
		success
		newDescription == role.description
		newAuthority == role.auth

		when:
		def requestmaps = TestRequestmap.list()

		then:
		'ROLE_USER'                          == requestmaps[0].rolePattern
		'ROLE_SUPERADMIN'                    == requestmaps[1].rolePattern
		'ROLE_SUPERADMIN,ROLE_FOO'           == requestmaps[2].rolePattern
		'ROLE_USER,ROLE_SUPERADMIN,ROLE_FOO' == requestmaps[3].rolePattern
		'ROLE_SUPERADMIN,ROLE_FOO'           == requestmaps[4].rolePattern
	}

	void 'delete role'() {

		when:
		springSecurityService.deleteRole role
		flushAndClear()

		then:
		4 == TestRequestmap.count()
		!TestRole.findByAuth(ROLE_ADMIN)
		assert !TestRequestmap.findByRolePattern(ROLE_ADMIN), 'Should have been deleted'

		when:
		def requestmaps = TestRequestmap.list()

		then:
		'ROLE_USER'          == requestmaps[0].rolePattern
		'ROLE_FOO'           == requestmaps[1].rolePattern
		'ROLE_USER,ROLE_FOO' == requestmaps[2].rolePattern
		'ROLE_FOO'           == requestmaps[3].rolePattern
	}

	private void createTestRequestmaps() {
		save new TestRequestmap('/user/**',         'ROLE_USER')
		save new TestRequestmap('/admin/role/**',   'ROLE_ADMIN')
		save new TestRequestmap('/admin/person/**', 'ROLE_ADMIN,ROLE_FOO')
		save new TestRequestmap('/admin/foo/**',    'ROLE_USER,ROLE_ADMIN,ROLE_FOO')
		save new TestRequestmap('/admin/super/**',  'ROLE_ADMIN,ROLE_FOO')

		flushAndClear()

		assert 5 == TestRequestmap.count()
	}

	void cleanup() {
		SpringSecurityUtils.securityConfig = oldConfig
	}
}
