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
package org.codehaus.groovy.grails.plugins.springsecurity

import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
/**
 * Unit tests for <code>SecurityRequestHolder</code>.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class SecurityRequestHolderTests extends GroovyTestCase {

	void testSetAndGet() {
		def request = new MockHttpServletRequest()
		def response = new MockHttpServletResponse()

		assertNull SecurityRequestHolder.request
		assertNull SecurityRequestHolder.response

		SecurityRequestHolder.set request, response

		assertSame request, SecurityRequestHolder.request
		assertSame response, SecurityRequestHolder.response
	}

	void testReset() {
		def request = new MockHttpServletRequest()
		def response = new MockHttpServletResponse()

		assertNull SecurityRequestHolder.request
		assertNull SecurityRequestHolder.response

		SecurityRequestHolder.set request, response

		assertSame request, SecurityRequestHolder.request
		assertSame response, SecurityRequestHolder.response

		SecurityRequestHolder.reset()

		assertNull SecurityRequestHolder.request
		assertNull SecurityRequestHolder.response
	}

	void testPrivateConstructor() {
		SecurityTestUtils.testPrivateConstructor SecurityRequestHolder
	}

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#tearDown()
	 */
	@Override
	protected void tearDown() {
		super.tearDown()
		SecurityRequestHolder.reset()
	}
}
