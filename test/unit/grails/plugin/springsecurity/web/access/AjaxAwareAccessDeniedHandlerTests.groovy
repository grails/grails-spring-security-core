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
package grails.plugin.springsecurity.web.access

import grails.plugin.springsecurity.FakeApplication
import grails.plugin.springsecurity.ReflectionUtils
import grails.plugin.springsecurity.SpringSecurityUtils
import grails.plugin.springsecurity.web.SecurityRequestHolder

import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.authentication.AuthenticationTrustResolverImpl
import org.springframework.security.authentication.RememberMeAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder as SCH
import org.springframework.security.web.PortResolverImpl
import org.springframework.security.web.savedrequest.HttpSessionRequestCache

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class AjaxAwareAccessDeniedHandlerTests extends GroovyTestCase {

	private final AjaxAwareAccessDeniedHandler handler = new AjaxAwareAccessDeniedHandler()
	private final FakeApplication application = new FakeApplication()
	private MockHttpServletRequest request = new MockHttpServletRequest()
	private MockHttpServletResponse response = new MockHttpServletResponse()

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#setUp()
	 */
	@Override
	protected void setUp() {
		super.setUp()
		handler.errorPage = '/fail'
		handler.ajaxErrorPage = '/ajaxFail'
		handler.portResolver = new PortResolverImpl()
		handler.authenticationTrustResolver = new AuthenticationTrustResolverImpl()
		handler.requestCache = new HttpSessionRequestCache()
		ReflectionUtils.application = application
		ReflectionUtils.setConfigProperty 'ajaxHeader', SpringSecurityUtils.AJAX_HEADER
		SecurityRequestHolder.set request, response
	}

	void testHandleAuthenticatedRememberMeRedirect() {

		handler.useForward = false

		SCH.context.authentication = new RememberMeAuthenticationToken('username', 'password', null)

		assertNull request.session.getAttribute(SpringSecurityUtils.SAVED_REQUEST)
		handler.handle request, response, new AccessDeniedException('fail')
		assertNotNull request.session.getAttribute(SpringSecurityUtils.SAVED_REQUEST)

		assertEquals 'http://localhost/fail', response.redirectedUrl
		assertNull response.forwardedUrl
	}

	void testHandleAuthenticatedRememberMeForward() {

		handler.useForward = true

		SCH.context.authentication = new RememberMeAuthenticationToken('username', 'password', null)

		assertNull request.session.getAttribute(SpringSecurityUtils.SAVED_REQUEST)
		handler.handle request, response, new AccessDeniedException('fail')
		assertNotNull request.session.getAttribute(SpringSecurityUtils.SAVED_REQUEST)

		assertNull response.redirectedUrl
		assertEquals '/fail', response.forwardedUrl
	}

	void testHandleAuthenticatedAjaxRedirect() {
		handler.useForward = false

		request.addHeader SpringSecurityUtils.AJAX_HEADER, 'XMLHttpRequest'

		handler.handle request, response, new AccessDeniedException('fail')

		assertEquals 'http://localhost/ajaxFail', response.redirectedUrl
		assertNull response.forwardedUrl
	}

	void testHandleAuthenticatedAjaxForward() {
		handler.useForward = true

		request.addHeader SpringSecurityUtils.AJAX_HEADER, 'XMLHttpRequest'

		handler.handle request, response, new AccessDeniedException('fail')

		assertEquals '/ajaxFail', response.forwardedUrl
		assertNull response.redirectedUrl
	}

	void testHandleAuthenticatedNotAjaxRedirect() {
		handler.useForward = false

		handler.handle request, response, new AccessDeniedException('fail')

		assertEquals 'http://localhost/fail', response.redirectedUrl
		assertNull response.forwardedUrl
	}

	void testHandleAuthenticatedNotAjaxForward() {
		handler.useForward = true

		handler.handle request, response, new AccessDeniedException('fail')

		assertEquals '/fail', response.forwardedUrl
		assertNull response.redirectedUrl
	}

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#tearDown()
	 */
	@Override
	protected void tearDown() {
		super.tearDown()
		SCH.context.authentication = null
		ReflectionUtils.application = null
		SecurityRequestHolder.reset()
	}
}
