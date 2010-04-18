package org.codehaus.groovy.grails.plugins.springsecurity;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.RequestCache;

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
public class AjaxAwareAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

	private String _ajaxSuccessUrl;
	private RequestCache _requestCache;

   /**
    * {@inheritDoc}
    * @see org.springframework.security.web.authentication.AbstractAuthenticationTargetUrlRequestHandler#determineTargetUrl(
    * 	javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
    */
   @Override
	protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response) {
   	if (SpringSecurityUtils.isAjax(request)) {
   		return _ajaxSuccessUrl;
   	}
   	return super.determineTargetUrl(request, response);
   }

	/**
	 * Dependency injection for the Ajax success url, e.g. '/login/ajaxSuccess'
	 * @param ajaxSuccessUrl the url
	 */
	public void setAjaxSuccessUrl(final String ajaxSuccessUrl) {
		_ajaxSuccessUrl = ajaxSuccessUrl;
	}

	/**
	 * {@inheritDoc}
	 * @see org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler#onAuthenticationSuccess(
	 * 	javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse,
	 * 	org.springframework.security.core.Authentication)
	 */
	@Override
	public void onAuthenticationSuccess(final HttpServletRequest request, final HttpServletResponse response,
			final Authentication authentication) throws ServletException, IOException {
		super.onAuthenticationSuccess(request, response, authentication);
		// always remove the saved request
		_requestCache.removeRequest(request, response);
	}

	/**
	 * {@inheritDoc}
	 * @see org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler#setRequestCache(
	 * 	org.springframework.security.web.savedrequest.RequestCache)
	 */
	@Override
	public void setRequestCache(RequestCache requestCache) {
		super.setRequestCache(requestCache);
		_requestCache = requestCache;
	}
}
