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

import grails.transaction.Transactional

import org.grails.core.util.ClassPropertyFetcher
import grails.core.DefaultGrailsApplication
import org.springframework.core.annotation.AnnotationUtils
import org.springframework.security.authentication.AuthenticationTrustResolverImpl
import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder as SCH
import org.springframework.security.core.userdetails.User

/**
 * Unit tests for SpringSecurityService.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class SpringSecurityServiceTests extends GroovyTestCase {

	private SpringSecurityService service = new SpringSecurityService()

	@Override
	protected void setUp() {
		super.setUp()
		ReflectionUtils.application = new DefaultGrailsApplication(config: new ConfigObject())
	}

	/**
	 * Test transactional.
	 */
	void testTransactional() {
		assert !ClassPropertyFetcher.forClass(SpringSecurityService).getPropertyValue('transactional')
		assert SpringSecurityService.methods.any { AnnotationUtils.findAnnotation(it, Transactional) }
	}

	/**
	 * Test getPrincipal().
	 */
	void testPrincipalAuthenticated() {
		assert !service.principal
		authenticate 'role1'
		assert service.principal
	}

	/**
	 * Test encodePassword().
	 */
	void testEncodePassword() {
		service.passwordEncoder = [encodePassword: { String pwd, salt -> pwd + '_encoded' }]
		assert 'passw0rd_encoded' == service.encodePassword('passw0rd')
	}

	void testClearCachedRequestmaps() {
		boolean resetCalled = false
		service.objectDefinitionSource = [reset: { -> resetCalled = true }]

		service.clearCachedRequestmaps()

		assert resetCalled
	}

	void testGetAuthentication() {
		assert !service.authentication?.principal
		authenticate 'role1'
		assert service.authentication
	}

	void testIsLoggedIn() {
		service.authenticationTrustResolver = new AuthenticationTrustResolverImpl()
		assert !service.isLoggedIn()
		authenticate 'role1'
		assert service.isLoggedIn()
	}

	private void authenticate(roles) {
		def authorities = SpringSecurityUtils.parseAuthoritiesString(roles)
		def principal = new User('username', 'password', true, true, true, true, authorities)
		def authentication = new TestingAuthenticationToken(principal, null, authorities)
		authentication.authenticated = true
		SCH.context.authentication = authentication
	}

	@Override
	protected void tearDown() {
		super.tearDown()
		SecurityTestUtils.logout()
		SpringSecurityUtils.securityConfig = null
		ReflectionUtils.application = null
	}
}
