/* Copyright 2013-2015 SpringSource.
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
package grails.plugin.springsecurity

import static org.springframework.security.authentication.dao.DaoAuthenticationProvider.USER_NOT_FOUND_PASSWORD
import grails.plugin.springsecurity.authentication.encoding.DigestAuthPasswordEncoder

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class DigestAuthPasswordEncoderTests extends GroovyTestCase {

	def daoAuthenticationProvider
	def passwordEncoder

	void testInitialize() {

		def providerPasswordEncoder = daoAuthenticationProvider.passwordEncoder
		assert passwordEncoder.is(providerPasswordEncoder)
		assert !(passwordEncoder instanceof DigestAuthPasswordEncoder)

		def digestAuthPasswordEncoder = new DigestAuthPasswordEncoder(realm: 'realm')
		assert digestAuthPasswordEncoder.initializing

		// ok since initializing is true
		digestAuthPasswordEncoder.encodePassword USER_NOT_FOUND_PASSWORD, null

		String message = shouldFail(IllegalArgumentException) {
			digestAuthPasswordEncoder.encodePassword 'otherPassword', null
		}
		assert 'Salt is required and must be the username' == message

		digestAuthPasswordEncoder.encodePassword 'otherPassword', 'theusername'

		// reset and we should be back to standard approach

		digestAuthPasswordEncoder.resetInitializing()

		assert !digestAuthPasswordEncoder.initializing

		message = shouldFail(IllegalArgumentException) {
			digestAuthPasswordEncoder.encodePassword USER_NOT_FOUND_PASSWORD, null
		}
		assert 'Salt is required and must be the username' == message

		message = shouldFail(IllegalArgumentException) {
			digestAuthPasswordEncoder.encodePassword 'otherPassword', null
		}
		assert 'Salt is required and must be the username' == message

		digestAuthPasswordEncoder.encodePassword 'otherPassword', 'theusername'
	}
}
