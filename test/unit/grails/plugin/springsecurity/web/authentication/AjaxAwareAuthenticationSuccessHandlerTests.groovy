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
package grails.plugin.springsecurity.web.authentication

import grails.plugin.springsecurity.SpringSecurityUtils
import grails.plugin.springsecurity.web.SecurityRequestHolder

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

	private static final String AJAX_SUCCESS_URL = '/ajaxSuccessUrl'
	private static final String DEFAULT_TARGET_URL = '/defaultTargetUrl'

	private final AjaxAwareAuthenticationSuccessHandler handler = new AjaxAwareAuthenticationSuccessHandler()
	private MockHttpServletRequest request = new MockHttpServletRequest()
	private MockHttpServletResponse response = new MockHttpServletResponse()

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#setUp()
	 */
	@Override
	protected void setUp() {
		super.setUp()
		handler.defaultTargetUrl = DEFAULT_TARGET_URL
		handler.ajaxSuccessUrl = AJAX_SUCCESS_URL

		def config = new ConfigObject()
		config.ajaxHeader = 'ajaxHeader'
		SpringSecurityUtils.securityConfig = config
		SecurityRequestHolder.set request, response
	}

	void testDetermineTargetUrl_Ajax() {

		handler.alwaysUseDefaultTargetUrl = true

		request.addHeader 'ajaxHeader', 'XMLHttpRequest'

		assertEquals AJAX_SUCCESS_URL, handler.determineTargetUrl(
				request, new MockHttpServletResponse())
	}

	void testDetermineTargetUrl_NotAjax() {
		assertEquals DEFAULT_TARGET_URL, handler.determineTargetUrl(
				new MockHttpServletRequest(), new MockHttpServletResponse())
	}

	void testOnAuthenticationSuccess() {
		Authentication authentication = new TestingAuthenticationToken('username', 'password')

		String expectedRedirect = 'expectedRedirect'
		SavedRequest savedRequest = [getRedirectUrl: { -> expectedRedirect }] as SavedRequest
		boolean removeRequestCalled = false
		handler.requestCache = [removeRequest: { req, res -> removeRequestCalled = true },
		                         getRequest: { req, res -> savedRequest }] as RequestCache
		String redirectUrl
		handler.redirectStrategy = [sendRedirect: { req, res, url -> redirectUrl = url }] as RedirectStrategy

		handler.onAuthenticationSuccess(request, response, authentication)

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
		grails.util.Holders.config = null
		SecurityRequestHolder.reset()
	}
}
