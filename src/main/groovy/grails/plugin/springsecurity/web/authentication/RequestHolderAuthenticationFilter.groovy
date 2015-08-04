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
package grails.plugin.springsecurity.web.authentication

import javax.servlet.FilterChain
import javax.servlet.ServletException
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import javax.servlet.http.HttpSession

import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter

import grails.plugin.springsecurity.SpringSecurityUtils
import grails.plugin.springsecurity.web.SecurityRequestHolder
import groovy.transform.CompileStatic

/**
 * Extends the default {@link UsernamePasswordAuthenticationFilter} to store the
 * request and response in the {@link SecurityRequestHolder}.
 *
 * @deprecated will be removed and replaced with
 *             grails.plugin.springsecurity.web.SecurityRequestHolderFilter at
 *             the beginning of the filter chain
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
@Deprecated
@CompileStatic
class RequestHolderAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	/** Whether to store the last attempted username in the session. */
	Boolean storeLastUsername

	@Override
	void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
		SecurityRequestHolder.set((HttpServletRequest)request, (HttpServletResponse)response)
		try {
			super.doFilter request, response, chain
		}
		finally {
			SecurityRequestHolder.reset()
		}
	}

	@Override
	Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

		if (storeLastUsername) {
			// Place the last username attempted into HttpSession for views
			HttpSession session = request.getSession(false)
			if (!session && allowSessionCreation) {
				session = request.session
			}

			session?.setAttribute SpringSecurityUtils.SPRING_SECURITY_LAST_USERNAME_KEY, (obtainUsername(request) ?: '').trim()
		}

		super.attemptAuthentication request, response
	}

	@Override
	void afterPropertiesSet() {
		super.afterPropertiesSet()
		assert storeLastUsername != null, 'storeLastUsername must be set'
	}
}
