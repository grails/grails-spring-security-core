/* Copyright 2006-2012 the original author or authors.
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
