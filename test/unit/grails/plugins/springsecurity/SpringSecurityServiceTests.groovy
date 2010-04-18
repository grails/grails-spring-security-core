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
package grails.plugins.springsecurity

import org.codehaus.groovy.grails.commons.ConfigurationHolder as CH
import org.codehaus.groovy.grails.plugins.springsecurity.SecurityTestUtils
import org.codehaus.groovy.grails.plugins.springsecurity.SpringSecurityUtils

import org.springframework.security.authentication.AuthenticationTrustResolverImpl
import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.authority.GrantedAuthorityImpl
import org.springframework.security.core.context.SecurityContextHolder as SCH
import org.springframework.security.core.userdetails.User

/**
 * Unit tests for SpringSecurityService.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class SpringSecurityServiceTests extends GroovyTestCase {

	private _service

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#setUp()
	 */
	@Override
	protected void setUp() {
		super.setUp()
		_service = new SpringSecurityService()
		CH.config = new ConfigObject()
	}

	/**
	 * Test transactional.
	 */
	void testTransactional() {
		assertFalse _service.transactional
	}

	/**
	 * Test getPrincipal().
	 */
	void testPrincipalAuthenticated() {
		assertNull _service.principal
		authenticate 'role1'
		assertNotNull _service.principal
	}

	/**
	 * Test encodePassword().
	 */
	void testEncodePassword() {
		_service.passwordEncoder = [encodePassword: { String pwd, Object salt -> pwd + '_encoded' }]
		assertEquals 'passw0rd_encoded', _service.encodePassword('passw0rd')
	}

	void testClearCachedRequestmaps() {
		boolean resetCalled = false
		_service.objectDefinitionSource = [reset: { -> resetCalled = true }]

		_service.clearCachedRequestmaps()

		assertTrue resetCalled
	}

	void testGetAuthentication() {
		assertNull _service.authentication
		authenticate 'role1'
		assertNotNull _service.authentication
	}

	void testIsLoggedIn() {
		_service.authenticationTrustResolver = new AuthenticationTrustResolverImpl()
		assertFalse _service.isLoggedIn()
		authenticate 'role1'
		assertTrue _service.isLoggedIn()
	}

	void testReauthenticate() {
		_service.authenticationTrustResolver = new AuthenticationTrustResolverImpl()
		assertFalse _service.isLoggedIn()
		authenticate 'role1'
		assertTrue _service.isLoggedIn()

		assertTrue _service.authentication instanceof TestingAuthenticationToken

		boolean removedFromCache = false
		def user = new User('username', 'password', true, true, true, true,
				[new GrantedAuthorityImpl('ROLE_USER')])

		_service.userDetailsService = [loadUserByUsername: { String username -> user }]
		_service.userCache = [removeUserFromCache: { String username -> removedFromCache = true }]

		_service.reauthenticate 'username'

		assertTrue _service.authentication instanceof UsernamePasswordAuthenticationToken
		assertTrue removedFromCache
	}

	private void authenticate(roles) {
		def authorities = SpringSecurityUtils.parseAuthoritiesString(roles)
		def principal = new User('username', 'password', true, true, true, true, authorities)
		def authentication = new TestingAuthenticationToken(principal, null, authorities)
		authentication.authenticated = true
		SCH.context.authentication = authentication
	}

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#tearDown()
	 */
	@Override
	protected void tearDown() {
		super.tearDown()
		SecurityTestUtils.logout()
		CH.config = null
		SpringSecurityUtils.securityConfig = null
	}
}
