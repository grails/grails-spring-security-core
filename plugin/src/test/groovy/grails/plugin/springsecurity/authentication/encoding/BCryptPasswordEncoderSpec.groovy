/* Copyright 2011-2016 the original author or authors.
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

import grails.plugin.springsecurity.AbstractUnitSpec

/**
 * Unit tests for BCryptPasswordEncoder.
 *
 * @author Burt Beckwith
 */
class BCryptPasswordEncoderSpec extends AbstractUnitSpec {

	private BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(10)

	void 'encode password'() {
		when:
		String password = 'passw0rd'
		String encoded = encoder.encodePassword(password, null)
		String encodedAgain = encoder.encodePassword(password, null)

		then:
		encoded != encodedAgain
		encoder.isPasswordValid encoded, password, null
	}
}
