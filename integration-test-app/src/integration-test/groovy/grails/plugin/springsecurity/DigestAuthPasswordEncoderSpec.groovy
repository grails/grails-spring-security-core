/* Copyright 2013-2016 the original author or authors.
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

import grails.plugin.springsecurity.authentication.encoding.DigestAuthPasswordEncoder

import static org.springframework.security.authentication.dao.DaoAuthenticationProvider.USER_NOT_FOUND_PASSWORD

/**
 * @author Burt Beckwith
 */
class DigestAuthPasswordEncoderSpec extends AbstractIntegrationSpec {

	def daoAuthenticationProvider
	def passwordEncoder

	void 'test initialize'() {
		when:
		def providerPasswordEncoder = daoAuthenticationProvider.passwordEncoder

		then:
		passwordEncoder.is providerPasswordEncoder
		!(passwordEncoder instanceof DigestAuthPasswordEncoder)

		when:
		def digestAuthPasswordEncoder = new DigestAuthPasswordEncoder(realm: 'realm')

		then:
		digestAuthPasswordEncoder.initializing

		when:
		// ok since initializing is true
		digestAuthPasswordEncoder.encodePassword USER_NOT_FOUND_PASSWORD, null

		then:
		noExceptionThrown()

		when:
		digestAuthPasswordEncoder.encodePassword 'otherPassword', null

		then:
		AssertionError e = thrown()

		e.message.startsWith 'Salt is required and must be the username.'

		when:
		digestAuthPasswordEncoder.encodePassword 'otherPassword', 'theusername'

		// reset and we should be back to standard approach

		digestAuthPasswordEncoder.resetInitializing()

		then:
		!digestAuthPasswordEncoder.initializing

		when:
		digestAuthPasswordEncoder.encodePassword USER_NOT_FOUND_PASSWORD, null

		then:
		e = thrown()
		e.message.startsWith 'Salt is required and must be the username.'

		when:
		digestAuthPasswordEncoder.encodePassword 'otherPassword', null

		then:
		e = thrown()
		e.message.startsWith 'Salt is required and must be the username.'

		when:
		digestAuthPasswordEncoder.encodePassword 'otherPassword', 'theusername'

		then:
		noExceptionThrown()
	}
}
