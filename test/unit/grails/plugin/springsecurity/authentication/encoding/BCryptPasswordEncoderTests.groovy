/* Copyright 2011-2013 SpringSource.
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
package grails.plugin.springsecurity.authentication.encoding

import grails.plugin.springsecurity.FakeApplication
import grails.plugin.springsecurity.ReflectionUtils

/**
 * Unit tests for BCryptPasswordEncoder.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class BCryptPasswordEncoderTests extends GroovyTestCase {

	private BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(10)

	@Override
	protected void setUp() {
		super.setUp()
		ReflectionUtils.application = new FakeApplication()
	}

	void testEncodePassword() {
		String password = 'passw0rd'
		String encoded = encoder.encodePassword(password, null)
		String encodedAgain = encoder.encodePassword(password, null)
		assertFalse encoded.equals(encodedAgain)
		assertTrue encoder.isPasswordValid(encoded, password, null)
	}

	@Override
	protected void tearDown() {
		super.tearDown()
		ReflectionUtils.application = null
	}
}
