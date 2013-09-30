/* Copyright 2006-2012 SpringSource.
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

import grails.plugin.springsecurity.SpringSecurityUtils

import org.codehaus.groovy.grails.commons.ConfigurationHolder as CH
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.web.RedirectStrategy

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class AjaxAwareAuthenticationFailureHandlerTests extends GroovyTestCase {

	private final _handler = new AjaxAwareAuthenticationFailureHandler()

	void testOnAuthenticationFailureNotAjax() {

		String defaultFailureUrl = '/defaultFailureUrl'
		_handler.defaultFailureUrl = defaultFailureUrl
		_handler.ajaxAuthenticationFailureUrl = '/ajaxAuthenticationFailureUrl'

		boolean redirectCalled = false
		def sendRedirect = { req, res, url ->
			redirectCalled = true
			assertEquals defaultFailureUrl, url
		}
		_handler.redirectStrategy = [sendRedirect: sendRedirect] as RedirectStrategy

		def config = new ConfigObject()
		config.ajaxHeader = 'ajaxHeader'
		SpringSecurityUtils.securityConfig = config

		_handler.onAuthenticationFailure new MockHttpServletRequest(),
			new MockHttpServletResponse(), new BadCredentialsException('fail')
		assertTrue redirectCalled
	}

	void testOnAuthenticationFailureAjax() {

		String ajaxAuthenticationFailureUrl = '/ajaxAuthenticationFailureUrl'
		_handler.defaultFailureUrl = '/defaultFailureUrl'
		_handler.ajaxAuthenticationFailureUrl = ajaxAuthenticationFailureUrl

		boolean redirectCalled = false
		def sendRedirect = { req, res, url ->
			redirectCalled = true
			assertEquals ajaxAuthenticationFailureUrl, url
		}
		_handler.redirectStrategy = [sendRedirect: sendRedirect] as RedirectStrategy

		def config = new ConfigObject()
		config.ajaxHeader = 'ajaxHeader'
		SpringSecurityUtils.securityConfig = config

		def request = new MockHttpServletRequest()
		request.addHeader 'ajaxHeader', 'XMLHttpRequest'
		_handler.onAuthenticationFailure request,
			new MockHttpServletResponse(), new BadCredentialsException('fail')
		assertTrue redirectCalled
	}

	void testAfterPropertiesSet() {
		shouldFail(IllegalArgumentException) {
			_handler.afterPropertiesSet()
		}

		_handler.ajaxAuthenticationFailureUrl = 'url'
		_handler.afterPropertiesSet()
	}

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#tearDown()
	 */
	@Override
	protected void tearDown() {
		super.tearDown()
		SpringSecurityUtils.resetSecurityConfig()
		CH.config = null
	}
}
