/* Copyright 2006-2016 the original author or authors.
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
import grails.plugin.springsecurity.web.SecurityRequestHolderFilter
import grails.plugin.springsecurity.web.authentication.GrailsUsernamePasswordAuthenticationFilter
import grails.plugin.springsecurity.web.authentication.logout.MutableLogoutFilter
import grails.plugin.springsecurity.web.filter.GrailsAnonymousAuthenticationFilter
import grails.plugin.springsecurity.web.filter.GrailsRememberMeAuthenticationFilter
import org.springframework.beans.factory.NoSuchBeanDefinitionException
import org.springframework.beans.factory.support.GenericBeanDefinition
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.access.ExceptionTranslationFilter
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor
import org.springframework.security.web.context.SecurityContextPersistenceFilter
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter
import org.springframework.web.filter.GenericFilterBean
import org.springframework.web.filter.HttpPutFormContentFilter
import test.TestRole
import test.TestUser
import test.TestUserRole

import javax.servlet.FilterChain
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse
import java.util.concurrent.Callable
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

import static org.springframework.beans.factory.config.BeanDefinition.SCOPE_PROTOTYPE
import static org.springframework.beans.factory.support.AbstractBeanDefinition.AUTOWIRE_BY_NAME

/**
 * Integration tests for <code>SpringSecurityUtils</code>.
 *
 * @author Burt Beckwith
 */
class SpringSecurityUtilsIntegrationSpec extends AbstractIntegrationSpec {

	def securityFilterChains
	SpringSecurityService springSecurityService

	private static final String username = 'username'
	private static final String otherUsername = 'other'
	private static TestUser testUser

	void setup() {
		if (testUser) return

		TestUser.withNewTransaction {
			testUser = save(new TestUser(loginName: username, passwrrd: 'password'))
			def role = save(new TestRole(auth: 'ROLE_ADMIN', description: 'admin'))
			TestUserRole.create testUser, role

			def user = save(new TestUser(loginName: otherUsername, passwrrd: 'password'))
			TestUserRole.create user, role
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
		10 == map.size()
		map[Integer.MIN_VALUE + 10] instanceof SecurityRequestHolderFilter
		map[300] instanceof SecurityContextPersistenceFilter
		map[400] instanceof MutableLogoutFilter
		map[800] instanceof GrailsUsernamePasswordAuthenticationFilter
		map[1400] instanceof SecurityContextHolderAwareRequestFilter
		map[1500] instanceof GrailsRememberMeAuthenticationFilter
		map[1600] instanceof GrailsAnonymousAuthenticationFilter
		map[1800] instanceof HttpPutFormContentFilter
		map[1900] instanceof ExceptionTranslationFilter
		map[2000] instanceof FilterSecurityInterceptor

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
		11 == map.size()
		map[410] instanceof DummyFilter

		when:
		def filters = securityFilterChains[0].filters

		then:
		filters[0] instanceof SecurityRequestHolderFilter
		filters[1] instanceof SecurityContextPersistenceFilter
		filters[2] instanceof MutableLogoutFilter
		filters[3] instanceof DummyFilter
		filters[4] instanceof GrailsUsernamePasswordAuthenticationFilter
		filters[5] instanceof SecurityContextHolderAwareRequestFilter
		filters[6] instanceof GrailsRememberMeAuthenticationFilter
		filters[7] instanceof GrailsAnonymousAuthenticationFilter
		filters[8] instanceof HttpPutFormContentFilter
		filters[9] instanceof ExceptionTranslationFilter
		filters[10] instanceof FilterSecurityInterceptor
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
			assert springSecurityService.loggedIn, "should be authenticated in a new thread"

			SpringSecurityUtils.doWithAuth username, {
				assert springSecurityService.loggedIn
				assert username == springSecurityService.principal.username
			}

			assert springSecurityService.loggedIn, 'should not have reset auth in a new thread'
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
		assert springSecurityService.loggedIn, 'should still be authenticated in main thread'
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
			assert springSecurityService.loggedIn, "should appear authenticated in a new thread"

			SpringSecurityUtils.doWithAuth otherUsername, {
				assert springSecurityService.loggedIn
				assert otherUsername == springSecurityService.principal.username
			}

			assert springSecurityService.loggedIn, 'should not have reset auth'
		}

		then:
		assert springSecurityService.loggedIn, 'should still be authenticated'
		assert username == springSecurityService.principal.username, 'should still be unauthenticated in main thread'
	}

	void 'thread pool'() {
		given:
		def threadPool = Executors.newFixedThreadPool(1)
		assert !springSecurityService.isLoggedIn()

		expect: "authentication propagates into thread pool"
		// doWithAuth: Simulate security context from session
		username == SpringSecurityUtils.doWithAuth(username) {
			assert springSecurityService.principal.username == username, "correct username in main thread"
			// use thread pool: simulate using e.g. Grails Async Framework
			// developer may think "security context is bound automatically, no need to use doWithAuth"
			return getPrincipalInThreadPool(threadPool)
		}

		and: "authentication propagates into thread pool again"
		// Simulate second HTTP request by different user. Uses same (servlet container) thread.
		// BUG: User in thread is still `user`
		otherUsername == SpringSecurityUtils.doWithAuth(otherUsername) {
			assert springSecurityService.principal.username == otherUsername, "correct username in main thread"
			return getPrincipalInThreadPool(threadPool)
		}
	}

	void 'doWithAuth in thread pool'() {
		given:
		def threadPool = Executors.newFixedThreadPool(2)

		// Prepare two user context to simulate session.
		def userContext = SecurityContextHolder.createEmptyContext()
		SecurityContextHolder.context = userContext
		SpringSecurityUtils.reauthenticate(username, null)
		def otherUserContext = SecurityContextHolder.createEmptyContext()
		SecurityContextHolder.context = otherUserContext
		SpringSecurityUtils.reauthenticate(otherUsername, null)

		Closure runAsync = { Closure c ->
			threadPool.submit(new Runnable() {
				@Override
				void run() throws Exception {
					c()
				}
			})
		}

		// A potential fix for the bug in the above spec might be to wrap every method that runs in a different thread in a doWithAuth
		Closure someMethod = { String principal, CompletableFuture<String> futureForPrincipal ->
			String principalInThread = SpringSecurityUtils.doWithAuth(principal) {
				// do some work
				sleep(1000)
				// just for testing:
				return springSecurityService.principal.username
			}
			futureForPrincipal.complete(principalInThread)
		}

		Closure anotherMethod = { String principal, CompletableFuture<String> futureForPrincipal ->
			SpringSecurityUtils.doWithAuth(principal) {
				// do some work
				// queue another background task
				runAsync someMethod.curry(principal, futureForPrincipal)
				// do more work: someMethod should be running now as well
				sleep(250)
				// someMethod still running. finishes after this method finishes
			}
		}

		when:
		"user calls anotherLongRunningBackgroundTask"
		// Request from user: Context is bound from session
		SecurityContextHolder.context = userContext
		// user calls anotherLongRunningBackgroundTask: Now both threads in the pool have inherited his security context
		def future = new CompletableFuture()
		runAsync anotherMethod.curry(username, future)

		then:
		"Correct user in background task"
		username == future.get()

		when:
		"otherUser calls anotherLongRunningBackgroundTask"
		// Request from otherUser: Context is bound from session
		SecurityContextHolder.context = otherUserContext
		def otherFuture = new CompletableFuture()
		runAsync anotherMethod.curry(otherUsername, otherFuture)

		then:
		"Correct user in background task"
		// Still the same bug: While someMethod was waiting for 1000 ms anotherMethod already completed and `doWithAuth`
		// reset the authorization to the original one: user
		otherUsername == otherFuture.get()
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

	private String getPrincipalInThreadPool(ExecutorService executorService) {
		executorService.submit(new Callable<String>() {
			@Override
			String call() throws Exception {
				springSecurityService.principal.username
			}
		}).get()
	}
}

class DummyFilter extends GenericFilterBean {
	void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) {}
}
