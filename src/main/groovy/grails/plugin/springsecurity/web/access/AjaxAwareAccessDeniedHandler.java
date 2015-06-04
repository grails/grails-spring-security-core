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
package grails.plugin.springsecurity.web.access;

import grails.plugin.springsecurity.ReflectionUtils;
import grails.plugin.springsecurity.SpringSecurityUtils;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.PortResolver;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.util.Assert;

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
public class AjaxAwareAccessDeniedHandler implements AccessDeniedHandler, InitializingBean {

	protected String errorPage;
	protected String ajaxErrorPage;
	protected PortResolver portResolver;
	protected AuthenticationTrustResolver authenticationTrustResolver;
	protected boolean useForward = true;
	protected RequestCache requestCache;

	public void handle(final HttpServletRequest request, final HttpServletResponse response,
			final AccessDeniedException e) throws IOException, ServletException {

		if (e != null && isLoggedIn() && authenticationTrustResolver.isRememberMe(getAuthentication())) {
			// user has a cookie but is getting bounced because of IS_AUTHENTICATED_FULLY,
			// so Spring Security won't save the original request
			requestCache.saveRequest(request, response);
		}

		if (response.isCommitted()) {
			return;
		}

		boolean ajaxError = ajaxErrorPage != null && SpringSecurityUtils.isAjax(request);
		if (errorPage == null && !ajaxError) {
			response.sendError(HttpServletResponse.SC_FORBIDDEN, e.getMessage());
			return;
		}

		if (useForward && (errorPage != null || ajaxError)) {
			// Put exception into request scope (perhaps of use to a view)
			request.setAttribute(WebAttributes.ACCESS_DENIED_403, e);
			response.setStatus(HttpServletResponse.SC_FORBIDDEN);
			request.getRequestDispatcher(ajaxError ? ajaxErrorPage : errorPage).forward(request, response);
			return;
		}

		String redirectUrl;
		String serverURL = ReflectionUtils.getGrailsServerURL();
		if (serverURL == null) {
			boolean includePort = true;
			String scheme = request.getScheme();
			String serverName = request.getServerName();
			int serverPort = portResolver.getServerPort(request);
			String contextPath = request.getContextPath();
			boolean inHttp = "http".equals(scheme.toLowerCase());
			boolean inHttps = "https".equals(scheme.toLowerCase());

			if (inHttp && (serverPort == 80)) {
				includePort = false;
			}
			else if (inHttps && (serverPort == 443)) {
				includePort = false;
			}
			redirectUrl = scheme + "://" + serverName + ((includePort) ? (":" + serverPort) : "") + contextPath;
		}
		else {
			redirectUrl = serverURL;
		}

		if (ajaxError) {
			redirectUrl += ajaxErrorPage;
		}
		else if (errorPage != null) {
			redirectUrl += errorPage;
		}
		response.sendRedirect(response.encodeRedirectURL(redirectUrl));
	}

	protected Authentication getAuthentication() {
		return SecurityContextHolder.getContext() == null ? null :
		       SecurityContextHolder.getContext().getAuthentication();
	}

	protected boolean isLoggedIn() {
		Authentication authentication = getAuthentication();
		if (authentication == null) {
			return false;
		}
		return !authenticationTrustResolver.isAnonymous(authentication);
	}

	/**
	 * Dependency injection for the error page, e.g. '/login/denied'.
	 * @param page the page
	 */
	public void setErrorPage(final String page) {
		Assert.isTrue(page == null || page.startsWith("/"), "ErrorPage must begin with '/'");
		errorPage = page;
	}

	/**
	 * Dependency injection for the Ajax error page, e.g. '/login/ajaxDenied'.
	 * @param page the page
	 */
	public void setAjaxErrorPage(final String page) {
		Assert.isTrue(page == null || page.startsWith("/"), "Ajax ErrorPage must begin with '/'");
		ajaxErrorPage = page;
	}

	/**
	 * Dependency injection for the port resolver.
	 * @param resolver the resolver
	 */
	public void setPortResolver(final PortResolver resolver) {
		portResolver = resolver;
	}

	/**
	 * Dependency injection for the {@link AuthenticationTrustResolver}.
	 * @param resolver the resolver
	 */
	public void setAuthenticationTrustResolver(final AuthenticationTrustResolver resolver) {
		authenticationTrustResolver = resolver;
	}

	/**
	 * Dependency injection for whether to forward or redirect.
	 * @param forward if <code>true</code> forward to render the denied page, otherwise redirect
	 */
	public void setUseForward(boolean forward) {
		useForward = forward;
	}

	/**
	 * Dependency injection for the request cache.
	 * @param cache the cache
	 */
	public void setRequestCache(RequestCache cache) {
		requestCache = cache;
	}

	public void afterPropertiesSet() {
		Assert.notNull(portResolver, "portResolver is required");
		Assert.notNull(authenticationTrustResolver, "authenticationTrustResolver is required");
		Assert.notNull(requestCache, "requestCache is required");
	}
}
