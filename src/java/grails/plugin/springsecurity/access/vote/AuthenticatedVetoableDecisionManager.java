/* Copyright 2006-2015 the original author or authors.
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
package grails.plugin.springsecurity.access.vote;

import java.util.Collection;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.vote.AbstractAccessDecisionManager;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;

/**
 * Uses the affirmative-based logic for roles, i.e. any in the list will grant access, but allows
 * an authenticated voter to 'veto' access. This allows specification of roles and
 * <code>IS_AUTHENTICATED_FULLY</code> on one line in SecurityConfig.groovy.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
public class AuthenticatedVetoableDecisionManager extends AbstractAccessDecisionManager {

	public void decide(final Authentication authentication, final Object object, final Collection<ConfigAttribute> configAttributes)
			throws AccessDeniedException, InsufficientAuthenticationException {

		boolean authenticatedVotersGranted = checkAuthenticatedVoters(authentication, object, configAttributes);
		boolean otherVotersGranted = checkOtherVoters(authentication, object, configAttributes);

		if (logger.isTraceEnabled()) {
			logger.trace("decide(): authenticatedVotersGranted=" + authenticatedVotersGranted + " otherVotersGranted=" + otherVotersGranted);
		}

		if (!authenticatedVotersGranted && !otherVotersGranted) {
			checkAllowIfAllAbstainDecisions();
		}
	}

	/**
	 * Allow any {@link AuthenticatedVoter} to veto. If any voter denies,
	 * throw an exception; if any grant, return <code>true</code>;
	 * otherwise return <code>false</code> if all abstain.
	 */
	@SuppressWarnings({ "rawtypes", "unchecked" })
	protected boolean checkAuthenticatedVoters(final Authentication authentication, final Object object,
			final Collection<ConfigAttribute> configAttributes) {

		boolean grant = false;
		for (AccessDecisionVoter voter : getDecisionVoters()) {
			if (voter instanceof AuthenticatedVoter) {
				int result = voter.vote(authentication, object, configAttributes);
				switch (result) {
					case AccessDecisionVoter.ACCESS_GRANTED:
						grant = true;
						break;
					case AccessDecisionVoter.ACCESS_DENIED:
						deny();
						break;
					default: // abstain
						break;
				}
			}
		}
		return grant;
	}

	/**
	 * Check the other (non-{@link AuthenticatedVoter}) voters. If any voter grants,
	 * return true. If any voter denies, throw exception. Otherwise return <code>false</code>
	 * to indicate that all abstained.
	 */
	@SuppressWarnings({ "rawtypes", "unchecked" })
	protected boolean checkOtherVoters(Authentication authentication, Object object, Collection<ConfigAttribute> configAttributes) {
		int denyCount = 0;
		for (AccessDecisionVoter voter : getDecisionVoters()) {
			if (voter instanceof AuthenticatedVoter) {
				continue;
			}

			int result = voter.vote(authentication, object, configAttributes);
			switch (result) {
				case AccessDecisionVoter.ACCESS_GRANTED:
					return true;
				case AccessDecisionVoter.ACCESS_DENIED:
					denyCount++;
					break;
				default: // abstain
					break;
			}
		}

		if (denyCount > 0) {
			deny();
		}

		// all abstain
		return false;
	}

	protected void deny() {
		throw new AccessDeniedException(messages.getMessage(
				"AbstractAccessDecisionManager.accessDenied",
				"Access is denied"));
	}
}
