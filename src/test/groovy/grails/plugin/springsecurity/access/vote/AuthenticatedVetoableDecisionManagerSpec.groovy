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
package grails.plugin.springsecurity.access.vote

import grails.plugin.springsecurity.AbstractUnitSpec
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.access.SecurityConfig
import org.springframework.security.access.vote.AuthenticatedVoter
import org.springframework.security.access.vote.RoleVoter
import org.springframework.security.authentication.AnonymousAuthenticationToken
import org.springframework.security.authentication.RememberMeAuthenticationToken
import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority

/**
 * Unit tests for AuthenticatedVetoableDecisionManager.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class AuthenticatedVetoableDecisionManagerSpec extends AbstractUnitSpec {

	private AuthenticatedVetoableDecisionManager manager = new AuthenticatedVetoableDecisionManager([new AuthenticatedVoter(), new RoleVoter()])

	void 'decide with one role'() {
		when:
		manager.decide createAuthentication(['ROLE_USER']), null, createDefinition(['ROLE_USER', 'ROLE_ADMIN'])

		then:
		notThrown AccessDeniedException
	}

	void 'decide with more than required roles'() {
		when:
		manager.decide createAuthentication(['ROLE_USER', 'ROLE_ADMIN']), null, createDefinition(['ROLE_USER'])

		then:
		notThrown AccessDeniedException
	}

	void 'decide insufficient roles'() {
		when:
		manager.decide createAuthentication(['ROLE_USER']), null, createDefinition(['ROLE_ADMIN'])

		then:
		thrown AccessDeniedException
	}

	void 'decide with IS_AUTHENTICATED_FULLY'() {
		when:
		manager.decide createAuthentication(['ROLE_USER']), null, createDefinition(['ROLE_USER', 'IS_AUTHENTICATED_FULLY'])

		then:
		notThrown AccessDeniedException
	}

	void 'decide with IS_AUTHENTICATED_FULLY and remember-me'() {
		when:
		def auth = new RememberMeAuthenticationToken('key', 'principal', namesToAuthorities(['ROLE_USER']))
		manager.decide auth, null, createDefinition(['ROLE_USER', 'IS_AUTHENTICATED_FULLY'])

		then:
		thrown AccessDeniedException
	}

	void 'decide with AnonymousAuthenticationToken'() {
		when:
		def auth = new AnonymousAuthenticationToken('key', 'principal', namesToAuthorities(['ROLE_USER']))
		manager.decide auth, null, createDefinition(['ROLE_USER', 'IS_AUTHENTICATED_FULLY'])

		then:
		thrown AccessDeniedException
	}

	private Authentication createAuthentication(roleNames) {
		new TestingAuthenticationToken(null, null, namesToAuthorities(roleNames))
	}

	private List<GrantedAuthority> namesToAuthorities(roleNames) {
		roleNames.collect { new SimpleGrantedAuthority(it) }
	}

	private createDefinition(roleNames) {
		roleNames.collect { new SecurityConfig(it) }
	}
}
