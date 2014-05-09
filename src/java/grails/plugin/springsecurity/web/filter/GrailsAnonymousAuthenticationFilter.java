/* Copyright 2013-2014 SpringSource.
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

import grails.plugin.springsecurity.authentication.GrailsAnonymousAuthenticationToken;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

/**
 * Replaces org.springframework.security.web.authentication.AnonymousAuthenticationFilter.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
public class GrailsAnonymousAuthenticationFilter extends GenericFilterBean {

	protected final Logger log = LoggerFactory.getLogger(getClass());

   protected AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource;
   protected String key;

	@Override
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
			throws IOException, ServletException {

		applyAnonymousForThisRequest((HttpServletRequest)req);

		chain.doFilter(req, res);
	}

	protected void applyAnonymousForThisRequest(HttpServletRequest request) {
		if (SecurityContextHolder.getContext().getAuthentication() == null) {
			SecurityContextHolder.getContext().setAuthentication(createAuthentication(request));

			if (log.isDebugEnabled()) {
				log.debug("Populated SecurityContextHolder with anonymous token: '{}'",
						SecurityContextHolder.getContext().getAuthentication());
			}
		}
		else {
			if (log.isDebugEnabled()) {
				log.debug("SecurityContextHolder not populated with anonymous token, as it already contained: '{}'",
						SecurityContextHolder.getContext().getAuthentication());
			}
		}
	}

	protected Authentication createAuthentication(HttpServletRequest request) {
		return new GrailsAnonymousAuthenticationToken(key, authenticationDetailsSource.buildDetails(request));
	}

	/**
	 * Dependency injection for authenticationDetailsSource.
	 * @param source the source
	 */
	public void setAuthenticationDetailsSource(AuthenticationDetailsSource<HttpServletRequest, ?> source) {
		authenticationDetailsSource = source;
	}

	/**
	 * Dependency injection for key.
	 * @param key the key
	 */
	public void setKey(String key) {
		this.key = key;
	}

   @Override
	public void afterPropertiesSet() throws ServletException {
   	super.afterPropertiesSet();
   	Assert.notNull(authenticationDetailsSource, "authenticationDetailsSource must be set");
   	Assert.hasText(key, "key must be set");
   }
}
