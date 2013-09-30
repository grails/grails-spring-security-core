/* Copyright 2006-2013 SpringSource.
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
import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.web.RedirectStrategy
import org.springframework.security.web.savedrequest.RequestCache
import org.springframework.security.web.savedrequest.SavedRequest

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class AjaxAwareAuthenticationSuccessHandlerTests extends GroovyTestCase {

	private final _handler = new AjaxAwareAuthenticationSuccessHandler()

	private static final String AJAX_SUCCESS_URL = '/ajaxSuccessUrl'
	private static final String DEFAULT_TARGET_URL = '/defaultTargetUrl'

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#setUp()
	 */
	@Override
	protected void setUp() {
		super.setUp()
		_handler.defaultTargetUrl = DEFAULT_TARGET_URL
		_handler.ajaxSuccessUrl = AJAX_SUCCESS_URL

		def config = new ConfigObject()
		config.ajaxHeader = 'ajaxHeader'
		SpringSecurityUtils.securityConfig = config
	}

	void testDetermineTargetUrl_Ajax() {

		_handler.alwaysUseDefaultTargetUrl = true

		def request = new MockHttpServletRequest()
		request.addHeader 'ajaxHeader', 'XMLHttpRequest'

		assertEquals AJAX_SUCCESS_URL, _handler.determineTargetUrl(
				request, new MockHttpServletResponse())
	}

	void testDetermineTargetUrl_NotAjax() {
		assertEquals DEFAULT_TARGET_URL, _handler.determineTargetUrl(
				new MockHttpServletRequest(), new MockHttpServletResponse())
	}

	void testOnAuthenticationSuccess() {
		def request = new MockHttpServletRequest()
		def response = new MockHttpServletResponse()
		Authentication authentication = new TestingAuthenticationToken('username', 'password')

		String expectedRedirect = 'expectedRedirect'
		SavedRequest savedRequest = [getRedirectUrl: { -> expectedRedirect }] as SavedRequest
		boolean removeRequestCalled = false
		_handler.requestCache = [removeRequest: { req, res -> removeRequestCalled = true },
		                         getRequest: { req, res -> savedRequest }] as RequestCache
		String redirectUrl
		_handler.redirectStrategy = [sendRedirect: { req, res, url -> redirectUrl = url }] as RedirectStrategy

		_handler.onAuthenticationSuccess(request, response, authentication)

		assertTrue removeRequestCalled
		assertEquals expectedRedirect, redirectUrl
	}

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#tearDown()
	 */
	@Override
	protected void tearDown() {
		super.tearDown()
		SpringSecurityUtils.securityConfig = null
		CH.config = null
	}
}
