/* Copyright 2006-2014 SpringSource.
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
package grails.plugin.springsecurity.web.authentication

import grails.plugin.springsecurity.web.SecurityRequestHolder

import javax.servlet.FilterChain

import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class RequestHolderAuthenticationFilterTests extends GroovyTestCase {

	private RequestHolderAuthenticationFilter filter = new RequestHolderAuthenticationFilter()

	void testDoFilter() {
		assertNull SecurityRequestHolder.request
		assertNull SecurityRequestHolder.response

		def request = new MockHttpServletRequest()
		def response = new MockHttpServletResponse()

		boolean chainCalled = false
		def chain = [doFilter: { req, res ->
			assertNotNull SecurityRequestHolder.request
			assertNotNull SecurityRequestHolder.response
			chainCalled = true
		}] as FilterChain

		filter.doFilter request, response, chain

		assertTrue chainCalled
		assertNull SecurityRequestHolder.request
		assertNull SecurityRequestHolder.response
	}
}
