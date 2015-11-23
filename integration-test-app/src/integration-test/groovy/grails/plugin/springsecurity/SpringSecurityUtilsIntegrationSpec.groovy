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

import static org.springframework.beans.factory.config.BeanDefinition.SCOPE_PROTOTYPE
import static org.springframework.beans.factory.support.AbstractBeanDefinition.AUTOWIRE_BY_NAME

import javax.servlet.FilterChain
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse

import org.springframework.beans.factory.NoSuchBeanDefinitionException
import org.springframework.beans.factory.support.GenericBeanDefinition
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.access.ExceptionTranslationFilter
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor
import org.springframework.security.web.authentication.logout.LogoutFilter
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationFilter
import org.springframework.security.web.context.SecurityContextPersistenceFilter
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter
import org.springframework.web.filter.GenericFilterBean

import grails.plugin.springsecurity.userdetails.GrailsUser
import grails.plugin.springsecurity.web.authentication.RequestHolderAuthenticationFilter
import grails.plugin.springsecurity.web.filter.GrailsAnonymousAuthenticationFilter
import test.TestRole
import test.TestUser
import test.TestUserRole

/**
 * Integration tests for <code>SpringSecurityUtils</code>.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class SpringSecurityUtilsIntegrationSpec extends AbstractIntegrationSpec {

	def securityFilterChains
	def springSecurityService

	private static final String username = 'username'
	private static TestUser testUser

	void setup() {
		if (testUser) return

		TestUser.withNewTransaction {
			testUser = save(new TestUser(username, springSecurityService.encodePassword('password')))
			def role = save(new TestRole('ROLE_ADMIN', 'admin'))
			TestUserRole.create testUser, role, true

			def user = save(new TestUser('other', springSecurityService.encodePassword('password')))
			TestUserRole.create user, role, true
		}
	}

	void cleanupSpec() {
		TestUser.withNewTransaction {
			TestUserRole.deleteAll TestUserRole.list()
			TestRole.deleteAll TestRole.list()
			TestUser.deleteAll TestUser.list()
		}
	}

	void cleanup() {
		SecurityContextHolder.clearContext() // logout
	}

	void 'clientRegisterFilter'() {

		given:
		def map = SpringSecurityUtils.configuredOrderedFilters

		expect:
		8 == map.size()
		map[300] instanceof SecurityContextPersistenceFilter
		map[400] instanceof LogoutFilter
		map[800] instanceof RequestHolderAuthenticationFilter
		map[1400] instanceof SecurityContextHolderAwareRequestFilter
		map[1500] instanceof RememberMeAuthenticationFilter
		map[1600] instanceof GrailsAnonymousAuthenticationFilter
		map[1800] instanceof ExceptionTranslationFilter
		map[1900] instanceof FilterSecurityInterceptor

		when:
		SpringSecurityUtils.clientRegisterFilter 'foo', SecurityFilterPosition.LOGOUT_FILTER

		then:
		thrown AssertionError

		when:
		SpringSecurityUtils.clientRegisterFilter 'foo', SecurityFilterPosition.LOGOUT_FILTER.order + 10

		then:
		thrown NoSuchBeanDefinitionException

		when:
		SpringSecurityUtils.clientRegisterFilter 'passwordEncoder', SecurityFilterPosition.LOGOUT_FILTER.order + 10

		then:
		thrown ClassCastException

		when:
		grailsApplication.mainContext.registerBeanDefinition 'dummyFilter',
			new GenericBeanDefinition(beanClass: DummyFilter, scope: SCOPE_PROTOTYPE, autowireMode: AUTOWIRE_BY_NAME)

		SpringSecurityUtils.clientRegisterFilter 'dummyFilter', SecurityFilterPosition.LOGOUT_FILTER.order + 10

		then:
		9 == map.size()
		map[410] instanceof DummyFilter

		when:
		def filters = securityFilterChains[0].filters

		then:
		filters[0] instanceof SecurityContextPersistenceFilter
		filters[1] instanceof LogoutFilter
		filters[2] instanceof DummyFilter
		filters[3] instanceof RequestHolderAuthenticationFilter
		filters[4] instanceof SecurityContextHolderAwareRequestFilter
		filters[5] instanceof RememberMeAuthenticationFilter
		filters[6] instanceof GrailsAnonymousAuthenticationFilter
		filters[7] instanceof ExceptionTranslationFilter
		filters[8] instanceof FilterSecurityInterceptor
	}

	void 'reauthenticate'() {

		expect:
		!springSecurityService.loggedIn

		when:
		SpringSecurityUtils.reauthenticate username, null

		then:
		springSecurityService.loggedIn

		when:
		def principal = springSecurityService.principal

		then:
		principal instanceof GrailsUser
		['ROLE_ADMIN'] == principal.authorities.authority
		username == principal.username
	}

	void 'doWithAuth with a current auth'() {

		expect:
		!springSecurityService.loggedIn

		when:
		SpringSecurityUtils.reauthenticate username, null

		then:
		springSecurityService.loggedIn

		when:
		doInThread {
			assert !springSecurityService.loggedIn, "shouldn't appear authenticated in a new thread"

			SpringSecurityUtils.doWithAuth username, {
				assert springSecurityService.loggedIn
				assert username == springSecurityService.principal.username
			}

			assert !springSecurityService.loggedIn, 'should have reset auth'
		}

		then:
		assert springSecurityService.loggedIn, 'should still be authenticated in main thread'
	}

	void 'doWithAuth with a new auth'() {

		expect:
		!springSecurityService.loggedIn

		when:
		doInThread {
			assert !springSecurityService.loggedIn, "shouldn't appear authenticated in a new thread"

			SpringSecurityUtils.doWithAuth username, {
				assert springSecurityService.loggedIn
				assert username == springSecurityService.principal.username
			}

			assert !springSecurityService.loggedIn, 'should have reset auth'
		}

		then:
		assert !springSecurityService.loggedIn, 'should still be unauthenticated in main thread'
	}

	void 'doWithAuth with a new auth, existing'() {

		expect:
		!springSecurityService.loggedIn

		when:
		SpringSecurityUtils.reauthenticate username, null

		then:
		springSecurityService.loggedIn

		when:
		doInThread {
			assert !springSecurityService.loggedIn, "shouldn't appear authenticated in a new thread"

			SpringSecurityUtils.doWithAuth 'other', {
				assert springSecurityService.loggedIn
				assert 'other' == springSecurityService.principal.username
			}

			assert !springSecurityService.loggedIn, 'should have reset auth'
		}

		then:
		assert springSecurityService.loggedIn, 'should still be authenticated'
		assert username == springSecurityService.principal.username, 'should still be unauthenticated in main thread'
	}

	void 'getCurrentUser not logged in'() {
		expect:
		!springSecurityService.loggedIn
		!springSecurityService.currentUser
	}

	void 'getCurrentUser logged in'() {
		when:
		SpringSecurityUtils.reauthenticate username, null

		then:
		springSecurityService.loggedIn

		when:
		def currentUser = springSecurityService.currentUser

		then:
		currentUser
		currentUser.id == testUser.id
	}

	private void doInThread(Closure c) {
		Throwable exception

		Thread.start {
			try {
				c()
			}
			catch (Throwable e) {
				exception = e
			}
		}.join()

		if (exception) {
			throw exception
		}
	}
}

class DummyFilter extends GenericFilterBean {
	void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) {}
}
