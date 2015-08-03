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
package grails.plugin.springsecurity.web.filter

import grails.plugin.springsecurity.ReflectionUtils
import grails.plugin.springsecurity.web.access.intercept.TestApplication

import javax.servlet.FilterChain

import grails.core.GrailsApplication
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.access.vote.AuthenticatedVoter
import org.springframework.security.access.vote.RoleVoter
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler
import org.springframework.web.context.WebApplicationContext

/**
 * Unit tests for <code>IpAddressFilter</code>.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class IpAddressFilterTests extends GroovyTestCase {

	private final IpAddressFilter filter = new IpAddressFilter()
	private final TestApplication application = new TestApplication()

	protected void setUp() {
		super.setUp()
		def beans = [(GrailsApplication.APPLICATION_ID): application,
		             webExpressionHandler: new DefaultWebSecurityExpressionHandler(),
		             roleVoter: new RoleVoter(),
		             authenticatedVoter: new AuthenticatedVoter()]

		def ctx = [getBean: { String name, Class<?> c = null -> beans[name] },
		           containsBean: { String name -> beans.containsKey(name) } ] as WebApplicationContext
		application.mainContext = ctx
		ReflectionUtils.application = application
	}

	protected void tearDown() {
		super.tearDown()
		ReflectionUtils.application = null
	}

	void testAfterPropertiesSet() {

		shouldFail(IllegalArgumentException) {
			filter.afterPropertiesSet()
		}

		filter.ipRestrictions = ['/foo/**': '127.0.0.1',
		                         '/bar/**': '10.0.0.0/8',
		                         '/wahoo/**': '10.10.200.63']

		filter.afterPropertiesSet()
	}

	void testDoFilterHttpAllowed() {

		filter.ipRestrictions = ['/foo/**': '127.0.0.1',
		                         '/bar/**': '10.0.0.0/8',
		                         '/wahoo/**': '10.10.200.63',
		                         '/masked/**': '192.168.1.0/24']

		def request = new MockHttpServletRequest()
		def response = new MockHttpServletResponse()
		int chainCount = 0
		def chain = [doFilter: { req, res -> chainCount++ }] as FilterChain

		request.remoteAddr = '127.0.0.1'
		request.requestURI = '/foo/bar?x=123'
		filter.doFilter request, response, chain

		request.remoteAddr = '10.10.111.222'
		request.requestURI = '/bar/foo?x=123'
		filter.doFilter request, response, chain

		request.remoteAddr = '10.10.200.63'
		request.requestURI = '/wahoo/list'
		filter.doFilter request, response, chain

		request.remoteAddr = '63.161.169.137'
		request.requestURI = '/my/united/states/of/whatever'
		filter.doFilter request, response, chain

		request.remoteAddr = '192.168.1.123'
		request.requestURI = '/masked/shouldsucceed'
		filter.doFilter request, response, chain

		assert 5 == chainCount
	}

	void testDoFilterHttpDenied() {

		filter.ipRestrictions = ['/foo/**': '127.0.0.1',
		                         '/bar/**': '10.0.0.0/8',
		                         '/wahoo/**': '10.10.200.63',
		                         '/masked/**': '192.168.1.0/24']

		def request = new MockHttpServletRequest()
		def response
		int chainCount = 0
		def chain = [doFilter: { req, res -> chainCount++ }] as FilterChain

		request.remoteAddr = '63.161.169.137'

		request.requestURI = '/foo/bar?x=123'
		response = new MockHttpServletResponse()
		filter.doFilter request, response, chain
		assert 404 == response.status

		request.requestURI = '/bar/foo?x=123'
		response = new MockHttpServletResponse()
		filter.doFilter request, response, chain
		assert 404 == response.status

		request.requestURI = '/wahoo/list'
		response = new MockHttpServletResponse()
		filter.doFilter request, response, chain
		assert 404 == response.status

		request.requestURI = '/masked/shouldfail'
		response = new MockHttpServletResponse()
		filter.doFilter request, response, chain
		assert 404 == response.status

		assert 0 == chainCount
	}

	void testDoFilterMixIPv6IPv4() {

		filter.ipRestrictions = ['/foo/**': '127.0.0.1',
		                         '/bar/**': '10.0.0.0/8',
		                         '/wahoo/**': '10.10.200.63',
		                         '/masked/**': '192.168.1.0/24']

		def request = new MockHttpServletRequest()
		def response
		int chainCount = 0
		def chain = [doFilter: { req, res -> chainCount++ }] as FilterChain

		request.remoteAddr = 'fa:db8:85a3::8a2e:370:7334'

		request.requestURI = '/masked/bar?x=123'
		response = new MockHttpServletResponse()
		filter.doFilter request, response, chain
		assert 404 == response.status

		assert 0 == chainCount
	}
}
