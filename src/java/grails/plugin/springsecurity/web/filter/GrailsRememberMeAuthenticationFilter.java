/* Copyright 2013-2015 the original author or authors.
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
package grails.plugin.springsecurity.web.filter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationFilter;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.util.Assert;

/**
 * Stores a SavedRequest so remember-me autologin gets redirected to requested url.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
public class GrailsRememberMeAuthenticationFilter extends RememberMeAuthenticationFilter {

	protected RequestCache requestCache;
	protected boolean createSessionOnSuccess = true;

	public GrailsRememberMeAuthenticationFilter(AuthenticationManager authenticationManager, RememberMeServices rememberMeServices,
	                                            RequestCache requestCache) {
		super(authenticationManager, rememberMeServices);
		this.requestCache = requestCache;
	}

	@Override
	protected void onSuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, Authentication authResult) {
		if (null == requestCache.getRequest(request, response)) {
			requestCache.saveRequest(request, response);
		}

		try {
			if (createSessionOnSuccess) {
				request.getSession(true);
			}
		}
		catch (IllegalStateException ignored) {
			// ignored
		}
	}

	/**
	 * Dependency injection for createSessionOnSuccess.
	 * @param createSessionOnSuccess
	 */
	public void setCreateSessionOnSuccess(boolean createSessionOnSuccess) {
		this.createSessionOnSuccess = createSessionOnSuccess;
	}

	@Override
	public void afterPropertiesSet() {
		super.afterPropertiesSet();
		Assert.notNull(requestCache, "requestCache is required");
	}
}
