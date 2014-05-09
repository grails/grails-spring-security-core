/* Copyright 2006-2014 SpringSource.
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
package grails.plugin.springsecurity.web.authentication.logout;

import java.io.IOException;
import java.util.List;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
public class MutableLogoutFilter extends LogoutFilter {

	protected final LogoutSuccessHandler logoutSuccessHandler;
	protected final Logger log = LoggerFactory.getLogger(getClass());

	protected List<LogoutHandler> handlers;

	/**
	 * Constructor.
	 * @param successHandler the logout success handler
	 */
	public MutableLogoutFilter(LogoutSuccessHandler successHandler) {
		super(successHandler, new DummyLogoutHandler());
		logoutSuccessHandler = successHandler;
	}

	/**
	 * {@inheritDoc}
	 * @see org.springframework.security.web.authentication.logout.LogoutFilter#doFilter(
	 * 	javax.servlet.ServletRequest, javax.servlet.ServletResponse, javax.servlet.FilterChain)
	 */
	@Override
	public void doFilter(final ServletRequest req, final ServletResponse res, final FilterChain chain)
			throws IOException, ServletException {

		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;

		if (requiresLogout(request, response)) {
			Authentication auth = SecurityContextHolder.getContext().getAuthentication();

			if (log.isDebugEnabled()) {
				log.debug("Logging out user '{}' and transferring to logout destination", auth);
			}

			for (LogoutHandler handler : handlers) {
				handler.logout(request, response, auth);
			}

			logoutSuccessHandler.onLogoutSuccess(request, response, auth);

			return;
		}

		chain.doFilter(request, response);
	}

	/**
	 * Dependency injection for the logout handlers.
	 * @param l the handlers
	 */
	public void setHandlers(final List<LogoutHandler> l) {
		handlers = l;
	}

	/**
	 * Null logout handler that's used to provide a non-empty list of handlers to the base class.
	 * The real handlers will be after construction.
	 */
	protected static class DummyLogoutHandler implements LogoutHandler {
		public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
			// do nothing
		}
	}
}
