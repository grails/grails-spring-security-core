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

import org.codehaus.groovy.grails.commons.ClassPropertyFetcher
import org.codehaus.groovy.grails.commons.DefaultGrailsApplication
import org.springframework.core.annotation.AnnotationUtils
import org.springframework.security.authentication.AuthenticationTrustResolverImpl
import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder as SCH
import org.springframework.security.core.userdetails.User
import org.springframework.transaction.annotation.Transactional

/**
 * Unit tests for SpringSecurityService.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class SpringSecurityServiceTests extends GroovyTestCase {

	private SpringSecurityService service

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#setUp()
	 */
	@Override
	protected void setUp() {
		super.setUp()
		service = new SpringSecurityService()
		def config = new ConfigObject()
		grails.util.Holders.setConfig(config)
		ReflectionUtils.application = new DefaultGrailsApplication(config: config)
	}

	/**
	 * Test transactional.
	 */
	void testTransactional() {
		assertNull ClassPropertyFetcher.forClass(SpringSecurityService).getPropertyValue('transactional')
		assertTrue SpringSecurityService.methods.any { AnnotationUtils.findAnnotation(it, Transactional) }
	}

	/**
	 * Test getPrincipal().
	 */
	void testPrincipalAuthenticated() {
		assertNull service.principal
		authenticate 'role1'
		assertNotNull service.principal
	}

	/**
	 * Test encodePassword().
	 */
	void testEncodePassword() {
		service.passwordEncoder = [encodePassword: { String pwd, Object salt -> pwd + '_encoded' }]
		assertEquals 'passw0rd_encoded', service.encodePassword('passw0rd')
	}

	void testClearCachedRequestmaps() {
		boolean resetCalled = false
		service.objectDefinitionSource = [reset: { -> resetCalled = true }]

		service.clearCachedRequestmaps()

		assertTrue resetCalled
	}

	void testGetAuthentication() {
		assertNull service.authentication?.principal
		authenticate 'role1'
		assertNotNull service.authentication
	}

	void testIsLoggedIn() {
		service.authenticationTrustResolver = new AuthenticationTrustResolverImpl()
		assertFalse service.isLoggedIn()
		authenticate 'role1'
		assertTrue service.isLoggedIn()
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
		grails.util.Holders.setConfig(null)
		SpringSecurityUtils.securityConfig = null
		ReflectionUtils.application = null
	}
}
