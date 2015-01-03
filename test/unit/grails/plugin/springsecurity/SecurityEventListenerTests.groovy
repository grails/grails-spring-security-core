/* Copyright 2006-2015 SpringSource.
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

import org.springframework.security.access.event.AbstractAuthorizationEvent
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent
import org.springframework.security.authentication.event.AuthenticationSuccessEvent
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent
import org.springframework.security.core.userdetails.User
import org.springframework.security.web.authentication.switchuser.AuthenticationSwitchUserEvent

/**
 * Unit tests for SecurityEventListener.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class SecurityEventListenerTests extends GroovyTestCase {

	private SecurityEventListener listener
	private closures

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#setUp()
	 */
	@Override
	protected void setUp() {
		super.setUp()
		listener = new SecurityEventListener()
		closures = new ConfigObject()
		SpringSecurityUtils.securityConfig = closures
	}

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#tearDown()
	 */
	@Override
	protected void tearDown() {
		super.tearDown()
		SpringSecurityUtils.resetSecurityConfig()
		grails.util.Holders.setConfig(null)
	}

	/**
	 * Test handling <code>InteractiveAuthenticationSuccessEvent</code>.
	 */
	void testInteractiveAuthenticationSuccessEvent() {

		boolean called = false
		closures.onInteractiveAuthenticationSuccessEvent = { e, appCtx -> called = true }

		listener.onApplicationEvent(new InteractiveAuthenticationSuccessEvent(
				new TestingAuthenticationToken("", ""), getClass()))

		assertTrue called
	}

	/**
	 * Test handling <code>AbstractAuthenticationFailureEvent</code>.
	 */
	void testAbstractAuthenticationFailureEvent() {

		boolean called = false
		closures.onAbstractAuthenticationFailureEvent = { e, appCtx -> called = true }

		listener.onApplicationEvent new AuthenticationFailureBadCredentialsEvent(
				new TestingAuthenticationToken("", ""), new BadCredentialsException('bad credentials'))

		assertTrue called
	}

	/**
	 * Test handling <code>AuthenticationSuccessEvent</code>.
	 */
	void testAuthenticationSuccessEvent() {

		boolean called = false
		closures.onAuthenticationSuccessEvent = { e, appCtx -> called = true }

		listener.onApplicationEvent(new AuthenticationSuccessEvent(
				new TestingAuthenticationToken("", "")))

		assertTrue called
	}

	/**
	 * Test handling <code>AbstractAuthorizationEvent</code>.
	 */
	void testAbstractAuthorizationEvent() {

		boolean called = false
		closures.onAuthorizationEvent = { e, appCtx -> called = true }

		listener.onApplicationEvent(new TestAuthorizationEvent())

		assertTrue called
	}

	/**
	 * Test handling <code>AuthenticationSwitchUserEvent</code>.
	 */
	void testAuthenticationSwitchUserEvent() {

		boolean called = false
		closures.onAuthenticationSwitchUserEvent = { e, appCtx -> called = true }

		def authentication = SecurityTestUtils.authenticate(['ROLE_FOO'])
		def targetUser = new User('username', 'password', true, true, true,
				true, authentication.authorities)

		listener.onApplicationEvent(new AuthenticationSwitchUserEvent(authentication, targetUser))

		assertTrue called
	}
}

/**
 * Dummy event (should be an anonymous inner class, but not possible in Groovy).
 */
class TestAuthorizationEvent extends AbstractAuthorizationEvent {
	TestAuthorizationEvent() {
		super(new Object())
	}
}
