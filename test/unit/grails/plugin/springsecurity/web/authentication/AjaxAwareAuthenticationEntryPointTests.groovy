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

import grails.plugin.springsecurity.FakeApplication
import grails.plugin.springsecurity.ReflectionUtils
import grails.plugin.springsecurity.SpringSecurityUtils

import org.codehaus.groovy.grails.commons.ConfigurationHolder as CH
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse

/**
 * Unit tests for WithAjaxAuthenticationProcessingFilterEntryPoint.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class AjaxAwareAuthenticationEntryPointTests extends GroovyTestCase {

	private final _entryPoint = new AjaxAwareAuthenticationEntryPoint()
	private final _application = new FakeApplication()

	private String _loginFormUrl = '/loginFormUrl'
	private String _ajaxLoginFormUrl = '/ajaxLoginFormUrl'

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#setUp()
	 */
	@Override
	protected void setUp() {
		super.setUp()
		_entryPoint.useForward = true
		_entryPoint.loginFormUrl = _loginFormUrl
		_entryPoint.ajaxLoginFormUrl = _ajaxLoginFormUrl
		ReflectionUtils.application = _application
		ReflectionUtils.setConfigProperty 'ajaxHeader', SpringSecurityUtils.AJAX_HEADER
	}

	/**
	 * Test commence() with Ajax false.
	 */
	void testCommenceNotAjax() {

		MockHttpServletRequest request = new MockHttpServletRequest()
		MockHttpServletResponse response = new MockHttpServletResponse()

		_entryPoint.commence request, response, null

		assertEquals _loginFormUrl, response.forwardedUrl
	}

	/**
	 * Test commence() with Ajax true.
	 */
	void testCommenceAjax() {

		MockHttpServletRequest request = new MockHttpServletRequest()
		MockHttpServletResponse response = new MockHttpServletResponse()

		request.addHeader SpringSecurityUtils.AJAX_HEADER, 'XHR'

		_entryPoint.commence request, response, null

		assertEquals _ajaxLoginFormUrl, response.forwardedUrl
	}

	/**
	 * Test setAjaxLoginFormUrl().
	 */
	void testSetAjaxLoginFormUrl() {
		shouldFail(IllegalArgumentException) {
			_entryPoint.ajaxLoginFormUrl = 'foo'
		}

		_entryPoint.ajaxLoginFormUrl = '/foo'
	}

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#tearDown()
	 */
	@Override
	protected void tearDown() {
		super.tearDown()
		SpringSecurityUtils.resetSecurityConfig()
		ReflectionUtils.application = null
		CH.config = null
	}
}
