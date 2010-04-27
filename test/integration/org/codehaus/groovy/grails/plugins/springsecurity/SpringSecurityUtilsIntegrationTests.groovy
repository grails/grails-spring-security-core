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
package org.codehaus.groovy.grails.plugins.springsecurity

import javax.servlet.FilterChain
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse

import org.springframework.beans.factory.NoSuchBeanDefinitionException
import org.springframework.beans.factory.support.AbstractBeanDefinition
import org.springframework.beans.factory.support.GenericBeanDefinition
import org.springframework.security.web.access.ExceptionTranslationFilter
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter
import org.springframework.security.web.authentication.logout.LogoutFilter
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationFilter
import org.springframework.security.web.context.SecurityContextPersistenceFilter
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter
import org.springframework.web.filter.GenericFilterBean

/**
 * Integration tests for <code>SpringSecurityUtils</code>.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class SpringSecurityUtilsIntegrationTests extends GroovyTestCase {

	def grailsApplication
	def springSecurityFilterChain

	void testClientRegisterFilter() {

		def map = SpringSecurityUtils.CONFIGURED_ORDERED_FILTERS
		assertEquals 8, map.size()
		assertTrue map[300] instanceof SecurityContextPersistenceFilter
		assertTrue map[400] instanceof LogoutFilter
		assertTrue map[800] instanceof RequestHolderAuthenticationFilter
		assertTrue map[1400] instanceof SecurityContextHolderAwareRequestFilter
		assertTrue map[1500] instanceof RememberMeAuthenticationFilter
		assertTrue map[1600] instanceof AnonymousAuthenticationFilter
		assertTrue map[1800] instanceof ExceptionTranslationFilter
		assertTrue map[1900] instanceof FilterSecurityInterceptor

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

		assertEquals 9, map.size()
		assertTrue map[410] instanceof DummyFilter

		def filters = springSecurityFilterChain.filterChainMap['/**']
		assertTrue filters[0] instanceof SecurityContextPersistenceFilter
		assertTrue filters[1] instanceof LogoutFilter
		assertTrue filters[2] instanceof DummyFilter
		assertTrue filters[3] instanceof RequestHolderAuthenticationFilter
		assertTrue filters[4] instanceof SecurityContextHolderAwareRequestFilter
		assertTrue filters[5] instanceof RememberMeAuthenticationFilter
		assertTrue filters[6] instanceof AnonymousAuthenticationFilter
		assertTrue filters[7] instanceof ExceptionTranslationFilter
		assertTrue filters[8] instanceof FilterSecurityInterceptor
	}
}

class DummyFilter extends GenericFilterBean {
	void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) {}
}
