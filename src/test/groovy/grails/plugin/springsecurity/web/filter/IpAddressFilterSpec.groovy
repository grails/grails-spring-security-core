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

import javax.servlet.FilterChain

import grails.plugin.springsecurity.AbstractUnitSpec
import grails.test.mixin.TestMixin
import grails.test.mixin.web.ControllerUnitTestMixin

/**
 * Unit tests for <code>IpAddressFilter</code>.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
@TestMixin(ControllerUnitTestMixin)
class IpAddressFilterSpec extends AbstractUnitSpec {

	private final IpAddressFilter filter = new IpAddressFilter()

	void 'afterPropertiesSet'() {

		when:
		filter.afterPropertiesSet()

		then:
		thrown AssertionError

		when:
		filter.ipRestrictions = ['/foo/**': '127.0.0.1',
		                         '/bar/**': '10.0.0.0/8',
		                         '/wahoo/**': '10.10.200.63']

		filter.afterPropertiesSet()

		then:
		notThrown AssertionError
	}

	void 'doFilter HTTP allowed'() {

		when:
		filter.ipRestrictions = ['/foo/**': '127.0.0.1',
		                         '/bar/**': '10.0.0.0/8',
		                         '/wahoo/**': '10.10.200.63',
		                         '/masked/**': '192.168.1.0/24']

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

		then:
		5 == chainCount
	}

	void 'doFilter HTTP denied'() {

		when:
		filter.ipRestrictions = ['/foo/**': '127.0.0.1',
		                         '/bar/**': '10.0.0.0/8',
		                         '/wahoo/**': '10.10.200.63',
		                         '/masked/**': '192.168.1.0/24']

		int chainCount = 0
		def chain = [doFilter: { req, res -> chainCount++ }] as FilterChain

		request.remoteAddr = '63.161.169.137'

		request.requestURI = '/foo/bar?x=123'

		filter.doFilter request, response, chain

		then:
		404 == response.status

		when:
		request.requestURI = '/bar/foo?x=123'
		response.reset()
		filter.doFilter request, response, chain

		then:
		404 == response.status

		when:
		request.requestURI = '/wahoo/list'
		response.reset()
		filter.doFilter request, response, chain

		then:
		404 == response.status

		when:
		request.requestURI = '/masked/shouldfail'
		response.reset()
		filter.doFilter request, response, chain

		then:
		404 == response.status

		0 == chainCount
	}

	void 'doFilter mix IPv6 and IPv4'() {

		when:
		filter.ipRestrictions = ['/foo/**': '127.0.0.1',
		                         '/bar/**': '10.0.0.0/8',
		                         '/wahoo/**': '10.10.200.63',
		                         '/masked/**': '192.168.1.0/24']

		int chainCount = 0
		def chain = [doFilter: { req, res -> chainCount++ }] as FilterChain

		request.remoteAddr = 'fa:db8:85a3::8a2e:370:7334'

		request.requestURI = '/masked/bar?x=123'

		filter.doFilter request, response, chain

		then:
		404 == response.status

		0 == chainCount
	}
}
