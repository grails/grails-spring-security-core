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
package grails.plugin.springsecurity.web.filter

import javax.servlet.FilterChain

import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse

/**
 * Unit tests for <code>IpAddressFilter</code>.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class IpAddressFilterTests extends GroovyTestCase {

	private final _filter = new IpAddressFilter()

	void testAfterPropertiesSet() {

		shouldFail(IllegalArgumentException) {
			_filter.afterPropertiesSet()
		}

		_filter.ipRestrictions = ['/foo/**': '127.0.0.1',
		                          '/bar/**': '10.0.0.0/8',
		                          '/wahoo/**': '10.10.200.63']

		_filter.afterPropertiesSet()
	}

	void testDoFilterHttpAllowed() {

		_filter.ipRestrictions = ['/foo/**': '127.0.0.1',
		                          '/bar/**': '10.0.0.0/8',
		                          '/wahoo/**': '10.10.200.63',
		                          '/masked/**': '192.168.1.0/24']

		def request = new MockHttpServletRequest()
		def response = new MockHttpServletResponse()
		int chainCount = 0
		def chain = [doFilter: { req, res -> chainCount++ }] as FilterChain

		request.remoteAddr = '127.0.0.1'
		request.requestURI = '/foo/bar?x=123'
		_filter.doFilter request, response, chain

		request.remoteAddr = '10.10.111.222'
		request.requestURI = '/bar/foo?x=123'
		_filter.doFilter request, response, chain

		request.remoteAddr = '10.10.200.63'
		request.requestURI = '/wahoo/list'
		_filter.doFilter request, response, chain

		request.remoteAddr = '63.161.169.137'
		request.requestURI = '/my/united/states/of/whatever'
		_filter.doFilter request, response, chain

		request.remoteAddr = '192.168.1.123'
		request.requestURI = '/masked/shouldsucceed'
		_filter.doFilter request, response, chain

		assertEquals 5, chainCount
	}

	void testDoFilterHttpDenied() {

		_filter.ipRestrictions = ['/foo/**': '127.0.0.1',
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
		_filter.doFilter request, response, chain
		assertEquals 404, response.status

		request.requestURI = '/bar/foo?x=123'
		response = new MockHttpServletResponse()
		_filter.doFilter request, response, chain
		assertEquals 404, response.status

		request.requestURI = '/wahoo/list'
		response = new MockHttpServletResponse()
		_filter.doFilter request, response, chain
		assertEquals 404, response.status

		request.requestURI = '/masked/shouldfail'
		response = new MockHttpServletResponse()
		_filter.doFilter request, response, chain
		assertEquals 404, response.status

		assertEquals 0, chainCount
	}

	void testDoFilterMixIPv6IPv4() {

		_filter.ipRestrictions = ['/foo/**': '127.0.0.1',
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
		_filter.doFilter request, response, chain
		assertEquals 404, response.status

		assertEquals 0, chainCount
	}
}
