/* Copyright 2011-2012 the original author or authors.
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
package grails.plugins.springsecurity

import org.codehaus.groovy.grails.plugins.springsecurity.FakeApplication
import org.codehaus.groovy.grails.plugins.springsecurity.ReflectionUtils

/**
 * Unit tests for BCryptPasswordEncoder.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class BCryptPasswordEncoderTests extends GroovyTestCase {

	private BCryptPasswordEncoder encoder = new BCryptPasswordEncoder()
	private final _application = new FakeApplication()

	@Override
	protected void setUp() {
		super.setUp()
		ReflectionUtils.application = _application
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
