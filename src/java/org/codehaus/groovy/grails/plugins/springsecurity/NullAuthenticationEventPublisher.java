package org.codehaus.groovy.grails.plugins.springsecurity;

import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
public class NullAuthenticationEventPublisher implements AuthenticationEventPublisher {

	/**
	 * {@inheritDoc}
	 * @see org.springframework.security.authentication.AuthenticationEventPublisher#publishAuthenticationFailure(
	 * 	org.springframework.security.core.AuthenticationException,
	 * 	org.springframework.security.core.Authentication)
	 */
	public void publishAuthenticationFailure(AuthenticationException e, Authentication a) {
		// do nothing
	}

	/**
	 * {@inheritDoc}
	 * @see org.springframework.security.authentication.AuthenticationEventPublisher#publishAuthenticationSuccess(
	 * 	org.springframework.security.core.Authentication)
	 */
	public void publishAuthenticationSuccess(Authentication a) {
		// do nothing
	}
}
