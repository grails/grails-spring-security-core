/* Copyright 2006-2016 the original author or authors.
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
package grails.plugin.springsecurity.web.authentication.logout

import groovy.util.logging.Slf4j

import javax.servlet.FilterChain
import javax.servlet.ServletException
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.authentication.logout.LogoutFilter
import org.springframework.security.web.authentication.logout.LogoutHandler
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler

import groovy.transform.CompileStatic

/**
 * @author Burt Beckwith
 */
@Slf4j
@CompileStatic
class MutableLogoutFilter extends LogoutFilter {

	protected final LogoutSuccessHandler logoutSuccessHandler

	/** Dependency injection for the logout handlers. */
	List<LogoutHandler> handlers

	/**
	 * Constructor.
	 * @param successHandler the logout success handler
	 */
	MutableLogoutFilter(LogoutSuccessHandler successHandler) {
		super(successHandler, new DummyLogoutHandler())
		logoutSuccessHandler = successHandler
	}

	@Override
	void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {

		HttpServletRequest request = (HttpServletRequest) req
		HttpServletResponse response = (HttpServletResponse) res

		if (!requiresLogout(request, response)) {
			chain.doFilter request, response
			return
		}

		Authentication auth = SecurityContextHolder.context.authentication
		log.debug "Logging out user '{}' and transferring to logout destination", auth

		handlers.each { LogoutHandler handler -> handler.logout request, response, auth }

		logoutSuccessHandler.onLogoutSuccess request, response, auth
	}

	/**
	 * Null logout handler that's used to provide a non-empty list of handlers to the base class.
	 * The real handlers will be after construction.
	 */
	protected static class DummyLogoutHandler implements LogoutHandler {
		void logout(HttpServletRequest req, HttpServletResponse res, Authentication a) {
			// do nothing
		}
	}
}
