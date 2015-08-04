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

import org.springframework.context.ApplicationContext
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.web.PortResolverImpl
import org.springframework.security.web.savedrequest.DefaultSavedRequest

import grails.plugin.springsecurity.web.SecurityRequestHolder

/**
 * Unit tests for SpringSecurityUtils.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class SpringSecurityUtilsTests extends GroovyTestCase {

	private application = new FakeApplication()
	private request = new MockHttpServletRequest()

	@Override
	protected void setUp() {
		super.setUp()
		ReflectionUtils.application = application
		SecurityRequestHolder.set request, null
	}

	/**
	 * Test authoritiesToRoles().
	 */
	void testAuthoritiesToRoles() {

		def roleNames = []
		def authorities = []
		(1..10).each { i ->
			String name = "role$i"
			roleNames << name
			authorities << new SimpleGrantedAuthority(name)
		}

		def roles = SpringSecurityUtils.authoritiesToRoles(authorities)
		assertSameContents roleNames, roles
	}

	/**
	 * Test authoritiesToRoles() when there is an authority with a null string.
	 */
	void testAuthoritiesToRolesNullAuthority() {

		def authorities = [new SimpleGrantedAuthority('role1'), new FakeAuthority()]

		shouldFail(AssertionError) {
			SpringSecurityUtils.authoritiesToRoles(authorities)
		}
	}

	/**
	 * Test getPrincipalAuthorities() when not authenticated.
	 */
	void testGetPrincipalAuthoritiesNoAuth() {
		assert !SpringSecurityUtils.principalAuthorities
	}

	/**
	 * Test getPrincipalAuthorities() when not authenticated.
	 */
	void testGetPrincipalAuthoritiesNoRoles() {
		SecurityTestUtils.authenticate()
		assert !SpringSecurityUtils.principalAuthorities
	}

	/**
	 * Test getPrincipalAuthorities().
	 */
	void testGetPrincipalAuthorities() {
		def authorities = (1..10).collect { new SimpleGrantedAuthority("role$it") }

		SecurityTestUtils.authenticate null, null, authorities

		assert authorities == SpringSecurityUtils.principalAuthorities
	}

	/**
	 * Test parseAuthoritiesString().
	 */
	void testParseAuthoritiesString() {
		String roleNames = 'role1,role2,role3'
		def roles = SpringSecurityUtils.parseAuthoritiesString(roleNames)

		assert 3 == roles.size()
		def expected = ['role1', 'role2', 'role3']
		def actual = roles.collect { authority -> authority.authority }
		assertSameContents expected, actual
	}

	/**
	 * Test retainAll().
	 */
	void testRetainAll() {
		def granted = [new SimpleGrantedAuthority('role1'),
		               new SimpleGrantedAuthority('role2'),
		               new SimpleGrantedAuthority('role3')]
		def required = [new SimpleGrantedAuthority('role1')]

		def expected = ['role1']
		assertSameContents expected, SpringSecurityUtils.retainAll(granted, required)
	}

	void testIsAjaxUsingParameterFalse() {
		assert !SpringSecurityUtils.isAjax(request)
	}

	void testIsAjaxUsingParameterTrue() {
		request.setParameter('ajax', 'true')

		assert SpringSecurityUtils.isAjax(request)
	}

	void testIsAjaxUsingHeaderFalse() {
		assert !SpringSecurityUtils.isAjax(request)
	}

	void testIsAjaxUsingHeaderXmlHttpRequest() {
		request.addHeader('X-Requested-With', 'XMLHttpRequest')

		assert SpringSecurityUtils.isAjax(request)
	}

	void testIsAjaxUsingHeaderTrue() {
		request.addHeader('X-Requested-With', 'true')

		assert !SpringSecurityUtils.isAjax(request)
	}

	void testIsAjaxUsingSavedRequestFalse() {

		def savedRequest = new DefaultSavedRequest(request, new PortResolverImpl())
		request.session.setAttribute(SpringSecurityUtils.SAVED_REQUEST, savedRequest)

		assert !SpringSecurityUtils.isAjax(request)
	}

	void testIsAjaxUsingSavedRequestTrue() {
		request.addHeader 'X-Requested-With', 'true'
		def savedRequest = new DefaultSavedRequest(request, new PortResolverImpl())
		request.session.setAttribute(SpringSecurityUtils.SAVED_REQUEST, savedRequest)

		assert !SpringSecurityUtils.isAjax(request)
	}

	void testIsAjaxUsingSavedRequestXmlHttpRequest() {
		request.addHeader 'X-Requested-With', 'XMLHttpRequest'
		def savedRequest = new DefaultSavedRequest(request, new PortResolverImpl())
		request.session.setAttribute(SpringSecurityUtils.SAVED_REQUEST, savedRequest)

		assert SpringSecurityUtils.isAjax(request)
	}

	void testIfAllGranted() {
		initRoleHierarchy ''
		SecurityTestUtils.authenticate(['ROLE_1', 'ROLE_2'], true)

		assert SpringSecurityUtils.ifAllGranted('ROLE_1')
		assert SpringSecurityUtils.ifAllGranted('ROLE_2')
		assert SpringSecurityUtils.ifAllGranted('ROLE_1,ROLE_2')
		assert !SpringSecurityUtils.ifAllGranted('ROLE_1,ROLE_2,ROLE_3')
		assert !SpringSecurityUtils.ifAllGranted('ROLE_3')

		assert SpringSecurityUtils.ifAllGranted([new SimpleGrantedAuthority('ROLE_1')])
		assert SpringSecurityUtils.ifAllGranted([new SimpleGrantedAuthority('ROLE_2')])
		assert SpringSecurityUtils.ifAllGranted([new SimpleGrantedAuthority('ROLE_1'), new SimpleGrantedAuthority('ROLE_2')])
		assert !SpringSecurityUtils.ifAllGranted([new SimpleGrantedAuthority('ROLE_1'), new SimpleGrantedAuthority('ROLE_2'), new SimpleGrantedAuthority('ROLE_3')])
		assert !SpringSecurityUtils.ifAllGranted([new SimpleGrantedAuthority('ROLE_3')])

		assert SpringSecurityUtils.ifAllGranted([newGrantedAuthorityImpl('ROLE_1')])
		assert SpringSecurityUtils.ifAllGranted([newGrantedAuthorityImpl('ROLE_2')])
		assert SpringSecurityUtils.ifAllGranted([newGrantedAuthorityImpl('ROLE_1'), newGrantedAuthorityImpl('ROLE_2')])
		assert !SpringSecurityUtils.ifAllGranted([newGrantedAuthorityImpl('ROLE_1'), newGrantedAuthorityImpl('ROLE_2'), newGrantedAuthorityImpl('ROLE_3')])
		assert !SpringSecurityUtils.ifAllGranted([newGrantedAuthorityImpl('ROLE_3')])
	}

	void testIfAllGranted_UsingHierarchy() {
		initRoleHierarchy 'ROLE_3 > ROLE_2 \n ROLE_2 > ROLE_1'
		SecurityTestUtils.authenticate(['ROLE_3'], true)

		assert SpringSecurityUtils.ifAllGranted('ROLE_1')
		assert SpringSecurityUtils.ifAllGranted('ROLE_2')
		assert SpringSecurityUtils.ifAllGranted('ROLE_1,ROLE_2')
		assert SpringSecurityUtils.ifAllGranted('ROLE_1,ROLE_2,ROLE_3')
		assert SpringSecurityUtils.ifAllGranted('ROLE_3')
		assert !SpringSecurityUtils.ifAllGranted('ROLE_4')

		assert SpringSecurityUtils.ifAllGranted([new SimpleGrantedAuthority('ROLE_1')])
		assert SpringSecurityUtils.ifAllGranted([new SimpleGrantedAuthority('ROLE_2')])
		assert SpringSecurityUtils.ifAllGranted([new SimpleGrantedAuthority('ROLE_1'), new SimpleGrantedAuthority('ROLE_2')])
		assert SpringSecurityUtils.ifAllGranted([new SimpleGrantedAuthority('ROLE_1'), new SimpleGrantedAuthority('ROLE_2'), new SimpleGrantedAuthority('ROLE_3')])
		assert SpringSecurityUtils.ifAllGranted([new SimpleGrantedAuthority('ROLE_3')])
		assert !SpringSecurityUtils.ifAllGranted([new SimpleGrantedAuthority('ROLE_4')])

		assert SpringSecurityUtils.ifAllGranted([newGrantedAuthorityImpl('ROLE_1')])
		assert SpringSecurityUtils.ifAllGranted([newGrantedAuthorityImpl('ROLE_2')])
		assert SpringSecurityUtils.ifAllGranted([newGrantedAuthorityImpl('ROLE_1'), newGrantedAuthorityImpl('ROLE_2')])
		assert SpringSecurityUtils.ifAllGranted([newGrantedAuthorityImpl('ROLE_1'), newGrantedAuthorityImpl('ROLE_2'), newGrantedAuthorityImpl('ROLE_3')])
		assert SpringSecurityUtils.ifAllGranted([newGrantedAuthorityImpl('ROLE_3')])
		assert !SpringSecurityUtils.ifAllGranted([newGrantedAuthorityImpl('ROLE_4')])
	}

	void testIfNotGranted() {
		initRoleHierarchy ''
		SecurityTestUtils.authenticate(['ROLE_1', 'ROLE_2'])

		assert !SpringSecurityUtils.ifNotGranted('ROLE_1')
		assert !SpringSecurityUtils.ifNotGranted('ROLE_2')
		assert !SpringSecurityUtils.ifNotGranted('ROLE_1,ROLE_2')
		assert !SpringSecurityUtils.ifNotGranted('ROLE_1,ROLE_2,ROLE_3')
		assert SpringSecurityUtils.ifNotGranted('ROLE_3')

		assert !SpringSecurityUtils.ifNotGranted([new SimpleGrantedAuthority('ROLE_1')])
		assert !SpringSecurityUtils.ifNotGranted([new SimpleGrantedAuthority('ROLE_2')])
		assert !SpringSecurityUtils.ifNotGranted([new SimpleGrantedAuthority('ROLE_1'), new SimpleGrantedAuthority('ROLE_2')])
		assert !SpringSecurityUtils.ifNotGranted([new SimpleGrantedAuthority('ROLE_1'), new SimpleGrantedAuthority('ROLE_2'), new SimpleGrantedAuthority('ROLE_3')])
		assert SpringSecurityUtils.ifNotGranted([new SimpleGrantedAuthority('ROLE_3')])

		assert !SpringSecurityUtils.ifNotGranted([newGrantedAuthorityImpl('ROLE_1')])
		assert !SpringSecurityUtils.ifNotGranted([newGrantedAuthorityImpl('ROLE_2')])
		assert !SpringSecurityUtils.ifNotGranted([newGrantedAuthorityImpl('ROLE_1'), newGrantedAuthorityImpl('ROLE_2')])
		assert !SpringSecurityUtils.ifNotGranted([newGrantedAuthorityImpl('ROLE_1'), newGrantedAuthorityImpl('ROLE_2'), newGrantedAuthorityImpl('ROLE_3')])
		assert SpringSecurityUtils.ifNotGranted([newGrantedAuthorityImpl('ROLE_3')])
	}

	void testIfNotGranted_UsingHierarchy() {
		initRoleHierarchy 'ROLE_3 > ROLE_2 \n ROLE_2 > ROLE_1'
		SecurityTestUtils.authenticate(['ROLE_3'])

		assert !SpringSecurityUtils.ifNotGranted('ROLE_1')
		assert !SpringSecurityUtils.ifNotGranted('ROLE_2')
		assert !SpringSecurityUtils.ifNotGranted('ROLE_1,ROLE_2')
		assert !SpringSecurityUtils.ifNotGranted('ROLE_1,ROLE_2,ROLE_3')
		assert !SpringSecurityUtils.ifNotGranted('ROLE_3')
		assert SpringSecurityUtils.ifNotGranted('ROLE_4')
	}

	void testIfAnyGranted() {
		initRoleHierarchy ''
		SecurityTestUtils.authenticate(['ROLE_1', 'ROLE_2'])

		assert SpringSecurityUtils.ifAnyGranted('ROLE_1')
		assert SpringSecurityUtils.ifAnyGranted('ROLE_2')
		assert SpringSecurityUtils.ifAnyGranted('ROLE_1,ROLE_2')
		assert SpringSecurityUtils.ifAnyGranted('ROLE_1,ROLE_2,ROLE_3')
		assert !SpringSecurityUtils.ifAnyGranted('ROLE_3')
	}

	void testIfAnyGranted_UsingHierarchy() {
		initRoleHierarchy 'ROLE_3 > ROLE_2 \n ROLE_2 > ROLE_1'
		SecurityTestUtils.authenticate(['ROLE_3'])

		assert SpringSecurityUtils.ifAnyGranted('ROLE_1')
		assert SpringSecurityUtils.ifAnyGranted('ROLE_2')
		assert SpringSecurityUtils.ifAnyGranted('ROLE_1,ROLE_2')
		assert SpringSecurityUtils.ifAnyGranted('ROLE_1,ROLE_2,ROLE_3')
		assert SpringSecurityUtils.ifAnyGranted('ROLE_3')
		assert !SpringSecurityUtils.ifAnyGranted('ROLE_4')
	}

	void testPrivateConstructor() {
		SecurityTestUtils.testPrivateConstructor SpringSecurityUtils
	}

	void testGetSecurityConfigType() {
		application.config.grails.plugin.springsecurity.securityConfigType = SecurityConfigType.Annotation
		assert 'Annotation' == SpringSecurityUtils.securityConfigType

		application.config.grails.plugin.springsecurity.securityConfigType = SecurityConfigType.Annotation.name()
		assert 'Annotation' == SpringSecurityUtils.securityConfigType

		application.config.grails.plugin.springsecurity.securityConfigType = 'Annotation'
		assert 'Annotation' == SpringSecurityUtils.securityConfigType

		application.config.grails.plugin.springsecurity.securityConfigType = SecurityConfigType.InterceptUrlMap
		assert 'InterceptUrlMap' == SpringSecurityUtils.securityConfigType

		application.config.grails.plugin.springsecurity.securityConfigType = SecurityConfigType.InterceptUrlMap.name()
		assert 'InterceptUrlMap' == SpringSecurityUtils.securityConfigType

		application.config.grails.plugin.springsecurity.securityConfigType = 'InterceptUrlMap'
		assert 'InterceptUrlMap' == SpringSecurityUtils.securityConfigType

		application.config.grails.plugin.springsecurity.securityConfigType = SecurityConfigType.Requestmap
		assert 'Requestmap' == SpringSecurityUtils.securityConfigType

		application.config.grails.plugin.springsecurity.securityConfigType = SecurityConfigType.Requestmap.name()
		assert 'Requestmap' == SpringSecurityUtils.securityConfigType

		application.config.grails.plugin.springsecurity.securityConfigType = 'Requestmap'
		assert 'Requestmap' == SpringSecurityUtils.securityConfigType
	}

	/**
	 * Check that two collections contain the same data, independent of collection class and order.
	 */
	private void assertSameContents(c1, c2) {
		assert c1.size() == c2.size()
		assert c1.containsAll(c2)
	}

	private void initRoleHierarchy(String hierarchy) {
		def roleHierarchy = new RoleHierarchyImpl(hierarchy: hierarchy)
		def ctx = [getBean: { String name -> roleHierarchy }, containsBean: { String name -> true }] as ApplicationContext
		SpringSecurityUtils.application = new FakeApplication() {
			ApplicationContext getMainContext() { ctx }
		}
	}

	private GrantedAuthority newGrantedAuthorityImpl(String name) {
		new org.springframework.security.core.authority.GrantedAuthorityImpl(name)
	}

	@Override
	protected void tearDown() {
		super.tearDown()
		SecurityTestUtils.logout()
		SpringSecurityUtils.resetSecurityConfig()
		SpringSecurityUtils.application = null
		ReflectionUtils.application = null
		SecurityRequestHolder.reset()
	}
}

class FakeAuthority implements GrantedAuthority {
	String authority
}
