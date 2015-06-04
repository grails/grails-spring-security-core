/*
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
package grails.plugin.springsecurity

import grails.plugin.springsecurity.web.authentication.logout.MutableLogoutFilter

import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices

import com.test.AdditionalLogoutHandler

/**
 * @author <a href='mailto:george@georgemcintosh.com'>George McIntosh</a>
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class AdditionalLogoutFiltersConfiguredTests extends GroovyTestCase {

	def grailsApplication

	void testAdditionalHandlersExist() {

		MutableLogoutFilter logoutFilter = grailsApplication.mainContext.logoutFilter
		assertEquals 3, logoutFilter.handlers.size()

		def expected = [AdditionalLogoutHandler, SecurityContextLogoutHandler, TokenBasedRememberMeServices].sort()
		def handlerClasses = logoutFilter.handlers.collect { it.class }.sort()

		assert expected == handlerClasses
	}

	void testInvoke() {

		MutableLogoutFilter logoutFilter = grailsApplication.mainContext.logoutFilter
		AdditionalLogoutHandler additionalLogoutHandler = grailsApplication.mainContext.additionalLogoutHandler
		additionalLogoutHandler.called = false

		logoutFilter.doFilter new MockHttpServletRequest(requestURI: '/j_spring_security_logout'), new MockHttpServletResponse(), new MockFilterChain()

		assert additionalLogoutHandler.called
	}
}
