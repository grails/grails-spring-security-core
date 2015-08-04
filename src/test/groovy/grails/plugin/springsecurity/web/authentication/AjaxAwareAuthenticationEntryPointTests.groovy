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

import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse

import grails.plugin.springsecurity.FakeApplication
import grails.plugin.springsecurity.ReflectionUtils
import grails.plugin.springsecurity.SpringSecurityUtils
import grails.plugin.springsecurity.web.SecurityRequestHolder

/**
 * Unit tests for WithAjaxAuthenticationProcessingFilterEntryPoint.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class AjaxAwareAuthenticationEntryPointTests extends GroovyTestCase {

	private final AjaxAwareAuthenticationEntryPoint entryPoint = new AjaxAwareAuthenticationEntryPoint()
	private final FakeApplication application = new FakeApplication()

	private String loginFormUrl = '/loginFormUrl'
	private String ajaxLoginFormUrl = '/ajaxLoginFormUrl'

	private MockHttpServletRequest request = new MockHttpServletRequest()
	private MockHttpServletResponse response = new MockHttpServletResponse()

	@Override
	protected void setUp() {
		super.setUp()
		entryPoint.useForward = true
		entryPoint.loginFormUrl = loginFormUrl
		entryPoint.ajaxLoginFormUrl = ajaxLoginFormUrl
		ReflectionUtils.application = application
		ReflectionUtils.setConfigProperty 'ajaxHeader', SpringSecurityUtils.AJAX_HEADER
		SecurityRequestHolder.set request, response
	}

	/**
	 * Test commence() with Ajax false.
	 */
	void testCommenceNotAjax() {

		entryPoint.commence request, response, null

		assert loginFormUrl == response.forwardedUrl
	}

	/**
	 * Test commence() with Ajax true.
	 */
	void testCommenceAjax() {

		request.addHeader SpringSecurityUtils.AJAX_HEADER, 'XMLHttpRequest'

		entryPoint.commence request, response, null

		assert ajaxLoginFormUrl == response.forwardedUrl
	}

	/**
	 * Test setAjaxLoginFormUrl().
	 */
	void testSetAjaxLoginFormUrl() {
		shouldFail(IllegalArgumentException) {
			entryPoint.ajaxLoginFormUrl = 'foo'
		}

		entryPoint.ajaxLoginFormUrl = '/foo'
	}

	@Override
	protected void tearDown() {
		super.tearDown()
		SpringSecurityUtils.resetSecurityConfig()
		ReflectionUtils.application = null
		SecurityRequestHolder.reset()
	}
}
