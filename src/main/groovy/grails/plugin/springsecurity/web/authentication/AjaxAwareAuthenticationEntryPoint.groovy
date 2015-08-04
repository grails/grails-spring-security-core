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

import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint

import grails.plugin.springsecurity.SpringSecurityUtils
import groovy.transform.CompileStatic

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
@CompileStatic
class AjaxAwareAuthenticationEntryPoint extends LoginUrlAuthenticationEntryPoint {

	protected String ajaxLoginFormUrl

	/**
	 * @param loginFormUrl URL where the login page can be found. Should either be relative to the web-app context path
	 * (include a leading {@code /}) or an absolute URL.
	 */
	AjaxAwareAuthenticationEntryPoint(String loginFormUrl) {
		super(loginFormUrl)
	}

	@Override
	protected String determineUrlToUseForThisRequest(HttpServletRequest req, HttpServletResponse res, AuthenticationException e) {
		ajaxLoginFormUrl && SpringSecurityUtils.isAjax(req) ? ajaxLoginFormUrl : loginFormUrl
	}

	@Override
	void commence(HttpServletRequest req, HttpServletResponse res, AuthenticationException e) throws IOException, ServletException {
		if ('true'.equalsIgnoreCase(req.getHeader('nopage'))) {
			res.sendError HttpServletResponse.SC_UNAUTHORIZED
			return
		}

		super.commence req, res, e
	}

	/**
	 * Dependency injection for the Ajax login form url, e.g. '/login/authAjax'.
	 * @param url the url
	 */
	void setAjaxLoginFormUrl(String url) {
		assert url == null || url.startsWith('/'), "ajaxLoginFormUrl must begin with '/'"
		ajaxLoginFormUrl = url
	}
}
