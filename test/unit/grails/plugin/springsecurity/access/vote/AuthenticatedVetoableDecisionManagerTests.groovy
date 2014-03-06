/* Copyright 2006-2014 SpringSource.
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
class AuthenticatedVetoableDecisionManagerTests extends GroovyTestCase {

	private AuthenticatedVetoableDecisionManager manager = new AuthenticatedVetoableDecisionManager()

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#setUp()
	 */
	@Override
	protected void setUp() {
		super.setUp()
		manager.decisionVoters = [new AuthenticatedVoter(), new RoleVoter()]
	}

	void testDecideHasOneRole() {
		manager.decide createAuthentication(['ROLE_USER']), null, createDefinition(['ROLE_USER', 'ROLE_ADMIN'])
	}

	void testDecideHasMoreThanRequiredRoles() {
		manager.decide createAuthentication(['ROLE_USER', 'ROLE_ADMIN']), null, createDefinition(['ROLE_USER'])
	}

	void testDecideInsufficientRoles() {
		shouldFail(AccessDeniedException) {
			manager.decide createAuthentication(['ROLE_USER']), null, createDefinition(['ROLE_ADMIN'])
		}
	}

	void testDecideAuthenticatedFully() {
		manager.decide createAuthentication(['ROLE_USER']), null, createDefinition(['ROLE_USER', 'IS_AUTHENTICATED_FULLY'])
	}

	void testDecideAuthenticatedFullyRemembered() {
		def auth = new RememberMeAuthenticationToken('key', 'principal', namesToAuthorities(['ROLE_USER']))
		shouldFail(AccessDeniedException) {
			manager.decide auth, null, createDefinition(['ROLE_USER', 'IS_AUTHENTICATED_FULLY'])
		}
	}

	void testDecideAuthenticatedFullyAnonymous() {
		def auth = new AnonymousAuthenticationToken('key', 'principal', namesToAuthorities(['ROLE_USER']))
		shouldFail(AccessDeniedException) {
			manager.decide auth, null, createDefinition(['ROLE_USER', 'IS_AUTHENTICATED_FULLY'])
		}
	}

	private Authentication createAuthentication(roleNames) {
		return new TestingAuthenticationToken(null, null, namesToAuthorities(roleNames))
	}

	private List<GrantedAuthority> namesToAuthorities(roleNames) {
		return roleNames.collect { new SimpleGrantedAuthority(it) }
	}

	private createDefinition(roleNames) {
		roleNames.collect { new SecurityConfig(it) }
	}
}
