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

import grails.plugin.springsecurity.userdetails.GrailsUser
import grails.plugin.springsecurity.web.authentication.RequestHolderAuthenticationFilter
import grails.plugin.springsecurity.web.filter.GrailsAnonymousAuthenticationFilter
import grails.test.mixin.TestMixin
import grails.test.mixin.integration.IntegrationTestMixin

import javax.servlet.FilterChain
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse

import org.junit.After
import org.junit.AfterClass
import org.junit.Before
import org.springframework.beans.factory.NoSuchBeanDefinitionException
import org.springframework.beans.factory.support.AbstractBeanDefinition
import org.springframework.beans.factory.support.GenericBeanDefinition
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.access.ExceptionTranslationFilter
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor
import org.springframework.security.web.authentication.logout.LogoutFilter
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationFilter
import org.springframework.security.web.context.SecurityContextPersistenceFilter
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter
import org.springframework.web.filter.GenericFilterBean

import test.TestRole
import test.TestUser
import test.TestUserRole

/**
 * Integration tests for <code>SpringSecurityUtils</code>.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
@TestMixin(IntegrationTestMixin)
class SpringSecurityUtilsIntegrationTests {

	def grailsApplication
	def springSecurityFilterChain
	def springSecurityService

	private String username = 'username'
	private static TestUser testUser

	@Before
	void setUp() {
		if (testUser) return

		TestUser.withNewTransaction {
			def user = new TestUser(loginName: username, enabld: true,
				passwrrd: springSecurityService.encodePassword('password')).save(failOnError: true)
			testUser = user
			def role = new TestRole(auth: 'ROLE_ADMIN', description: 'admin').save(failOnError: true)
			TestUserRole.create user, role, true

			user = new TestUser(loginName: 'other', enabld: true,
				passwrrd: springSecurityService.encodePassword('password')).save(failOnError: true)
			TestUserRole.create user, role, true
		}
	}

	@AfterClass
	static void removeTestUsers() {
		TestUser.withNewTransaction {
			TestUserRole.deleteAll(TestUserRole.list())
			TestRole.deleteAll(TestRole.list())
			TestUser.deleteAll(TestUser.list())
		}
	}

	@After
	void tearDown() {
		SecurityContextHolder.clearContext() // logout
	}

	void testClientRegisterFilter() {

		def map = SpringSecurityUtils.configuredOrderedFilters
		assert 8 == map.size()
		assert map[300] instanceof SecurityContextPersistenceFilter
		assert map[400] instanceof LogoutFilter
		assert map[800] instanceof RequestHolderAuthenticationFilter
		assert map[1400] instanceof SecurityContextHolderAwareRequestFilter
		assert map[1500] instanceof RememberMeAuthenticationFilter
		assert map[1600] instanceof GrailsAnonymousAuthenticationFilter
		assert map[1800] instanceof ExceptionTranslationFilter
		assert map[1900] instanceof FilterSecurityInterceptor

		shouldFail(IllegalArgumentException) {
			SpringSecurityUtils.clientRegisterFilter 'foo',
					SecurityFilterPosition.LOGOUT_FILTER
		}

		shouldFail(NoSuchBeanDefinitionException) {
			SpringSecurityUtils.clientRegisterFilter 'foo',
					SecurityFilterPosition.LOGOUT_FILTER.order + 10
		}

		shouldFail(ClassCastException) {
			SpringSecurityUtils.clientRegisterFilter 'passwordEncoder',
					SecurityFilterPosition.LOGOUT_FILTER.order + 10
		}

		grailsApplication.mainContext.registerBeanDefinition 'dummyFilter',
			new GenericBeanDefinition(beanClass: DummyFilter,
					scope: AbstractBeanDefinition.SCOPE_PROTOTYPE,
					autowireMode:AbstractBeanDefinition.AUTOWIRE_BY_NAME)

		SpringSecurityUtils.clientRegisterFilter 'dummyFilter',
				SecurityFilterPosition.LOGOUT_FILTER.order + 10

		assert 9 == map.size()
		assert map[410] instanceof DummyFilter

		def filterChainMap = springSecurityFilterChain.filterChainMap
		def filters = filterChainMap.values()[0]

		assert filters[0] instanceof SecurityContextPersistenceFilter
		assert filters[1] instanceof LogoutFilter
		assert filters[2] instanceof DummyFilter
		assert filters[3] instanceof RequestHolderAuthenticationFilter
		assert filters[4] instanceof SecurityContextHolderAwareRequestFilter
		assert filters[5] instanceof RememberMeAuthenticationFilter
		assert filters[6] instanceof GrailsAnonymousAuthenticationFilter
		assert filters[7] instanceof ExceptionTranslationFilter
		assert filters[8] instanceof FilterSecurityInterceptor
	}

	void testReauthenticate() {

		assert !springSecurityService.loggedIn

		SpringSecurityUtils.reauthenticate username, null

		assert springSecurityService.loggedIn
		def principal = springSecurityService.principal
		assert principal instanceof GrailsUser
		assert ['ROLE_ADMIN'] == principal.authorities.authority
		assert username == principal.username
	}

	void testDoWithAuth_CurrentAuth() {

		assert !springSecurityService.loggedIn
		SpringSecurityUtils.reauthenticate username, null
		assert springSecurityService.loggedIn

		Throwable otherException
		Thread.start {
			try {
				assert !springSecurityService.loggedIn, "shouldn't appear authenticated in a new thread"

				SpringSecurityUtils.doWithAuth username, {
					assert springSecurityService.loggedIn
					assert username == springSecurityService.principal.username
				}

				assert !springSecurityService.loggedIn, "should have reset auth"
			}
			catch (Throwable e) {
				otherException = e
			}
		}.join()
		if (otherException) {
			throw otherException
		}
		assert springSecurityService.loggedIn, "should still be authenticated in main thread"
	}

	void testDoWithAuth_NewAuth() {

		assert !springSecurityService.loggedIn

		Throwable otherException
		Thread.start {
			try {
				assert !springSecurityService.loggedIn, "shouldn't appear authenticated in a new thread"

				SpringSecurityUtils.doWithAuth username, {
					assert springSecurityService.loggedIn
					assert username == springSecurityService.principal.username
				}

				assert !springSecurityService.loggedIn, "should have reset auth"
			}
			catch (Throwable e) {
				otherException=e
			}
		}.join()
		if (otherException) {
			throw otherException
		}

		assert !springSecurityService.loggedIn, "should still be unauthenticated in main thread"
	}

	void testDoWithAuth_NewAuth_WithExisting() {

		assert !springSecurityService.loggedIn
		SpringSecurityUtils.reauthenticate username, null
		assert springSecurityService.loggedIn

		Throwable otherException
		Thread.start {
			try {
				assert !springSecurityService.loggedIn, "shouldn't appear authenticated in a new thread"

				SpringSecurityUtils.doWithAuth 'other', {
					assert springSecurityService.loggedIn
					assert 'other' == springSecurityService.principal.username
				}

				assert !springSecurityService.loggedIn, "should have reset auth"
			}
			catch (Throwable e) {
				otherException = e
			}
		}.join()
		if (otherException) {
			throw otherException
		}

		assert springSecurityService.loggedIn, 'should still be authenticated'
		assert username == springSecurityService.principal.username, 'should still be unauthenticated in main thread'
	}

	void testGetCurrentUser_NotLoggedIn() {
		assert !springSecurityService.loggedIn
		assert !springSecurityService.currentUser
	}

	void testGetCurrentUser_LoggedIn() {
		SpringSecurityUtils.reauthenticate username, null
		assert springSecurityService.loggedIn

		def currentUser = springSecurityService.currentUser
		assert currentUser
		assert currentUser.id == testUser.id
	}
}

class DummyFilter extends GenericFilterBean {
	void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) {}
}
