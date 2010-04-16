package org.codehaus.groovy.grails.plugins.springsecurity;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
public class AjaxAwareAuthenticationSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

	private String _ajaxSuccessUrl;

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
}
