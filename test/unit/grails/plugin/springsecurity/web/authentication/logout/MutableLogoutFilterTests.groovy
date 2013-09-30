/* Copyright 2006-2012 SpringSource.
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

	private final String _afterLogoutUrl = '/loggedout'
	private final _logoutSuccessHandler = new SimpleUrlLogoutSuccessHandler(
			defaultTargetUrl: _afterLogoutUrl)
	private final _handlers = []
	private final _filter = new MutableLogoutFilter(_logoutSuccessHandler)

	private int _logoutCount

	@Override
	protected void setUp() {
		super.setUp()
		(1..5).each {
			def handler = [logout: { req, res, auth -> _logoutCount++ }] as LogoutHandler
			_handlers << handler
		}
		_filter.handlers = _handlers
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
		_filter.doFilter request1, response1, chain1
		assertNull response1.redirectedUrl

		_filter.doFilter request2, response2, chain2
		assertNotNull response2.redirectedUrl

		assertTrue chain1Called
		assertFalse chain2Called
		assertEquals 5, _logoutCount
	}
}
