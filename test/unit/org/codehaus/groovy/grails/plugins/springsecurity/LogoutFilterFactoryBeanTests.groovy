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
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

import org.easymock.EasyMock
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.core.Authentication
import org.springframework.security.web.authentication.logout.LogoutFilter
import org.springframework.security.web.authentication.logout.LogoutHandler

/**
 * Unit tests for <code>LogoutFilterFactoryBean</code>.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class LogoutFilterFactoryBeanTests extends GroovyTestCase {

	private final LogoutFilterFactoryBean _factory = new LogoutFilterFactoryBean()

	/**
	 * Test isSingleton.
	 */
	void testIsSingleton() {
		assertTrue _factory.singleton
	}

	/**
	 * Test building a filter.
	 */
	void testFactory() {
		String url = '/after_logout'
		String filterProcessesUrl = '/j_spring_security_logout'

		Authentication authentication = SecurityTestUtils.authenticate()

		def request1 = new MockHttpServletRequest('GET', '/foo/bar')
		def response1 = new MockHttpServletResponse()
		def request2 = new MockHttpServletRequest('GET', filterProcessesUrl)
		def response2 = new MockHttpServletResponse()

		def handlers = []
		(1..5).each { handlers << EasyMock.createMock(LogoutHandler) }
		handlers.each { handler ->
			handler.logout(request2, response2, authentication)
			EasyMock.replay(handler)
		}

		_factory.logoutSuccessUrl = url
		_factory.handlers = handlers
		_factory.filterProcessesUrl = filterProcessesUrl
		assertNull _factory.object

		_factory.afterPropertiesSet()

		assertNotNull _factory.object
		assertEquals LogoutFilter, _factory.objectType
		assertTrue _factory.object instanceof LogoutFilter

		// now test the filter to ensure that it calls the handlers

		LogoutFilter filter = _factory.object

		FilterChain chain1 = EasyMock.createMock(FilterChain)
		FilterChain chain2 = EasyMock.createMock(FilterChain)
		chain1.doFilter(request1, response1)
		EasyMock.expectLastCall()
		EasyMock.replay(chain1, chain2)

		// not a logout url, so chain.doFilter() is called
		filter.doFilter(request1, response1, chain1)
		assertNull response1.redirectedUrl

		filter.doFilter(request2, response2, chain2)
		assertNotNull response2.redirectedUrl

		EasyMock.verify(handlers as Object[])
		EasyMock.verify(chain1, chain2)
	}

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#tearDown()
	 */
	@Override
	protected void tearDown() {
		super.tearDown()
		SecurityTestUtils.logout()
	}
}
