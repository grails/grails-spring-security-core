/* Copyright 2006-2013 SpringSource.
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
package grails.plugin.springsecurity.web.authentication.logout

import grails.plugin.springsecurity.SecurityTestUtils

import javax.servlet.FilterChain

import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.web.authentication.logout.LogoutHandler
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler

/**
 * Unit tests for MutableLogoutFilter.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class MutableLogoutFilterTests extends GroovyTestCase {

	private final String afterLogoutUrl = '/loggedout'
	private final logoutSuccessHandler = new SimpleUrlLogoutSuccessHandler(
			defaultTargetUrl: afterLogoutUrl)
	private final handlers = []
	private final filter = new MutableLogoutFilter(logoutSuccessHandler)

	private int logoutCount

	@Override
	protected void setUp() {
		super.setUp()
		(1..5).each {
			handlers << ([logout: { req, res, auth -> logoutCount++ }] as LogoutHandler)
		}
		filter.handlers = handlers
	}

	void testDoFilter() {
		String url = '/after_logout'
		String filterProcessesUrl = '/j_spring_security_logout'

		def authentication = SecurityTestUtils.authenticate()

		def request1 = new MockHttpServletRequest('GET', '/foo/bar')
		def response1 = new MockHttpServletResponse()
		def request2 = new MockHttpServletRequest('GET', filterProcessesUrl)
		def response2 = new MockHttpServletResponse()

		boolean chain1Called = false
		boolean chain2Called = false
		def chain1 = [doFilter: { req, res -> chain1Called = true }] as FilterChain
		def chain2 = [doFilter: { req, res -> chain2Called = true }] as FilterChain

		// not a logout url, so chain.doFilter() is called
		filter.doFilter request1, response1, chain1
		assertNull response1.redirectedUrl

		filter.doFilter request2, response2, chain2
		assertNotNull response2.redirectedUrl

		assertTrue chain1Called
		assertFalse chain2Called
		assertEquals 5, logoutCount
	}
}
