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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.util.Assert;

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
public class AjaxAwareAuthenticationEntryPoint extends LoginUrlAuthenticationEntryPoint {

	protected final Logger log = LoggerFactory.getLogger(getClass());

	protected String ajaxLoginFormUrl;
	protected RedirectStrategy redirectStrategy;

	/**
	 * @param loginFormUrl URL where the login page can be found. Should either be relative to the web-app context path
	 * (include a leading {@code /}) or an absolute URL.
	 */
	public AjaxAwareAuthenticationEntryPoint(String loginFormUrl) {
		super(loginFormUrl);
	}

	@Override
	protected String determineUrlToUseForThisRequest(final HttpServletRequest request,
			final HttpServletResponse response, final AuthenticationException e) {

		if (ajaxLoginFormUrl != null && SpringSecurityUtils.isAjax(request)) {
			return ajaxLoginFormUrl;
		}

		return getLoginFormUrl();
	}

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException e)
			throws IOException, ServletException {

		if ("true".equalsIgnoreCase(request.getHeader("nopage"))) {
			response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
			return;
		}

		String redirectUrl = null;

		if (isUseForward()) {

			if (isForceHttps() && "http".equals(request.getScheme())) {
				// First redirect the current request to HTTPS.
				// When that request is received, the forward to the login page will be used.
				redirectUrl = buildHttpsRedirectUrlForRequest(request);
			}

			if (redirectUrl == null) {
				String loginForm = determineUrlToUseForThisRequest(request, response, e);
				log.debug("Server side forward to: {}", loginForm);
				request.getRequestDispatcher(loginForm).forward(request, response);
				return;
			}
		}
		else {
			// redirect to login page. Use https if forceHttps true
			redirectUrl = buildRedirectUrlToLoginPage(request, response, e);
		}

		redirectStrategy.sendRedirect(request, response, redirectUrl);
	}

	/**
	 * Dependency injection for the Ajax login form url, e.g. '/login/authAjax'.
	 * @param url the url
	 */
	public void setAjaxLoginFormUrl(final String url) {
		Assert.isTrue(url == null || url.startsWith("/"), "ajaxLoginFormUrl must begin with '/'");
		ajaxLoginFormUrl = url;
	}

	/**
	 * Dependency injection for the RedirectStrategy.
	 * @param redirectStrategy redirectStrategy
	 */
	public void setRedirectStrategy(RedirectStrategy strategy) {
		redirectStrategy = strategy;
	}
}
