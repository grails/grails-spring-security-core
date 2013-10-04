/* Copyright 2013 SpringSource.
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

/**
 * Unit tests for PBKDF2PasswordEncoder.
 *
 * @author havoc AT defuse.ca
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class PBKDF2PasswordEncoderTests extends GroovyTestCase {

	private PBKDF2PasswordEncoder encoder = new PBKDF2PasswordEncoder()

	void testEncodePassword() {
		boolean failure = false
		100.times { int i ->
			String password = i
			String hash = encoder.encodePassword(password, null)
			String secondHash = encoder.encodePassword(password, null)
			if (hash.equals(secondHash)) {
				fail 'TWO HASHES ARE EQUAL'
			}

			String wrongPassword = i + 1
			if (encoder.isPasswordValid(hash, wrongPassword, null)) {
				fail 'WRONG PASSWORD ACCEPTED'
			}

			if (!encoder.isPasswordValid(hash, password, null)) {
				fail 'GOOD PASSWORD NOT ACCEPTED'
			}
		}
	}
}
