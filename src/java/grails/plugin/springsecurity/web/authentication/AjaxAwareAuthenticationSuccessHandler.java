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
package grails.plugin.springsecurity.web.authentication;

import grails.plugin.springsecurity.SpringSecurityUtils;

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

	protected String ajaxSuccessUrl;
	protected RequestCache requestCache;

	@Override
	public void onAuthenticationSuccess(final HttpServletRequest request, final HttpServletResponse response,
			final Authentication authentication) throws ServletException, IOException {

		// GPSPRINGSECURITYCORE-240
		if (SpringSecurityUtils.isAjax(request)) {
			requestCache.removeRequest(request, response);
		}

		try {
			if (SpringSecurityUtils.isAjax(request)) {
				clearAuthenticationAttributes(request);
				if (logger.isDebugEnabled()) {
					logger.debug("Redirecting to Ajax Success Url: " + ajaxSuccessUrl);
				}
				getRedirectStrategy().sendRedirect(request, response, ajaxSuccessUrl);
			}
			else {
				super.onAuthenticationSuccess(request, response, authentication);
			}
		}
		finally {
			// always remove the saved request
			requestCache.removeRequest(request, response);
		}
	}

	/**
	 * Dependency injection for the Ajax success url, e.g. '/login/ajaxSuccess'.
	 * @param url the url
	 */
	public void setAjaxSuccessUrl(final String url) {
		ajaxSuccessUrl = url;
	}

	@Override
	public void setRequestCache(RequestCache cache) {
		super.setRequestCache(cache);
		requestCache = cache;
	}
}
