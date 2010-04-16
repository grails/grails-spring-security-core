package org.codehaus.groovy.grails.plugins.springsecurity;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.ExceptionMappingAuthenticationFailureHandler;
import org.springframework.util.Assert;

/**
 * Ajax-aware failure handler that detects failed Ajax logins and redirects to the appropriate URL.
 *
 * @author Burt
 */
public class AjaxAwareAuthenticationFailureHandler extends ExceptionMappingAuthenticationFailureHandler implements InitializingBean {

	private String _ajaxAuthenticationFailureUrl;

	/**
	 * {@inheritDoc}
	 * @see org.springframework.security.web.authentication.ExceptionMappingAuthenticationFailureHandler#onAuthenticationFailure(
	 * 	javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse,
	 * 	org.springframework.security.core.AuthenticationException)
	 */
	@Override
	public void onAuthenticationFailure(final HttpServletRequest request, final HttpServletResponse response,
			final AuthenticationException exception) throws IOException, ServletException {

		if (SpringSecurityUtils.isAjax(request)) {
         getRedirectStrategy().sendRedirect(request, response, _ajaxAuthenticationFailureUrl);
		}
		else {
			super.onAuthenticationFailure(request, response, exception);
		}
	}

	/**
	 * Dependency injection for the Ajax auth fail url.
	 * @param url  the url
	 */
	public void setAjaxAuthenticationFailureUrl(final String url) {
		_ajaxAuthenticationFailureUrl = url;
	}

	/**
	 * {@inheritDoc}
	 * @see org.springframework.beans.factory.InitializingBean#afterPropertiesSet()
	 */
	public void afterPropertiesSet() {
		Assert.notNull(_ajaxAuthenticationFailureUrl, "ajaxAuthenticationFailureUrl is required");
	}
}
