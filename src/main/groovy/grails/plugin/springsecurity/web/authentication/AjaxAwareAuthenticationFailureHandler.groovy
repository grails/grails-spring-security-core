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

import org.springframework.beans.factory.InitializingBean
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.authentication.ExceptionMappingAuthenticationFailureHandler

import grails.plugin.springsecurity.SpringSecurityUtils
import groovy.transform.CompileStatic

/**
 * Ajax-aware failure handler that detects failed Ajax logins and redirects to the appropriate URL.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
@CompileStatic
class AjaxAwareAuthenticationFailureHandler extends ExceptionMappingAuthenticationFailureHandler implements InitializingBean {

	/** Dependency injection for the Ajax auth fail url. */
	String ajaxAuthenticationFailureUrl

	@Override
	void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException, ServletException {

		if (SpringSecurityUtils.isAjax(request)) {
			saveException request, exception
			redirectStrategy.sendRedirect request, response, ajaxAuthenticationFailureUrl
		}
		else {
			super.onAuthenticationFailure request, response, exception
		}
	}

	void afterPropertiesSet() {
		assert ajaxAuthenticationFailureUrl, 'ajaxAuthenticationFailureUrl is required'
	}
}
