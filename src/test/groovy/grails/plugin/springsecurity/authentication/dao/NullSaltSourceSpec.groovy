/* Copyright 2006-2016 the original author or authors.
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
package grails.plugin.springsecurity.authentication.dao

import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.User

import grails.plugin.springsecurity.AbstractUnitSpec

/**
 * Unit tests for <code>NullSaltSource</code>.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class NullSaltSourceSpec extends AbstractUnitSpec {

	void 'getSalt'() {
		when:
		def user = new User('username', 'password', true, true, true, true, [new SimpleGrantedAuthority('ROLE_USER')])

		then:
		!new NullSaltSource().getSalt(user)
	}
}
