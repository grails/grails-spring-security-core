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
package grails.plugin.springsecurity.web

import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse

import grails.plugin.springsecurity.SecurityTestUtils

/**
 * Unit tests for <code>SecurityRequestHolder</code>.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class SecurityRequestHolderTests extends GroovyTestCase {

	void testSetAndGet() {
		def request = new MockHttpServletRequest()
		def response = new MockHttpServletResponse()

		assert !SecurityRequestHolder.request
		assert !SecurityRequestHolder.response

		SecurityRequestHolder.set request, response

		assert request.is(SecurityRequestHolder.request)
		assert response.is(SecurityRequestHolder.response)
	}

	void testReset() {
		def request = new MockHttpServletRequest()
		def response = new MockHttpServletResponse()

		assert !SecurityRequestHolder.request
		assert !SecurityRequestHolder.response

		SecurityRequestHolder.set request, response

		assert request.is(SecurityRequestHolder.request)
		assert response.is(SecurityRequestHolder.response)

		SecurityRequestHolder.reset()

		assert !SecurityRequestHolder.request
		assert !SecurityRequestHolder.response
	}

	void testPrivateConstructor() {
		SecurityTestUtils.testPrivateConstructor SecurityRequestHolder
	}

	@Override
	protected void tearDown() {
		super.tearDown()
		SecurityRequestHolder.reset()
	}
}
