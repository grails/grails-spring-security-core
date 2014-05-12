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
package org.codehaus.groovy.grails.plugins.springsecurity

import grails.util.Holders as CH
import org.codehaus.groovy.grails.web.mapping.UrlMappingInfo
import org.codehaus.groovy.grails.web.servlet.mvc.GrailsWebRequest
import org.codehaus.groovy.grails.web.util.WebUtils
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.mock.web.MockServletContext
import org.springframework.security.access.SecurityConfig
import org.springframework.security.access.vote.AuthenticatedVoter
import org.springframework.security.access.vote.RoleVoter
import org.springframework.security.web.FilterInvocation
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler
import org.springframework.security.web.util.AntUrlPathMatcher

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class InterceptUrlMapFilterInvocationDefinitionTests extends GroovyTestCase {

	private _fid = new InterceptUrlMapFilterInvocationDefinition()
	private final _application = new FakeApplication()

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#setUp()
	 */
	@Override
	protected void setUp() {
		super.setUp()
		ReflectionUtils.application = _application
		_fid.urlMatcher = new AntUrlPathMatcher()
	}

	void testAfterPropertiesSet() {
		_fid.urlMatcher = null // simulate not having set it

		assertEquals 'url matcher is required', shouldFail(IllegalArgumentException) {
			_fid.afterPropertiesSet()
		}

		_fid.urlMatcher = new AntUrlPathMatcher()

		_fid.afterPropertiesSet()
	}

	void testStoreMapping() {

		assertEquals 0, _fid.configAttributeMap.size()

		_fid.storeMapping '/foo/bar', ['ROLE_ADMIN']
		assertEquals 1, _fid.configAttributeMap.size()

		_fid.storeMapping '/foo/bar', ['ROLE_USER']
		assertEquals 1, _fid.configAttributeMap.size()

		_fid.storeMapping '/other/path', ['ROLE_SUPERUSER']
		assertEquals 2, _fid.configAttributeMap.size()
	}

	void testInitialize() {
		ReflectionUtils.setConfigProperty('interceptUrlMap',
				['/foo/**': 'ROLE_ADMIN',
				 '/bar/**': ['ROLE_BAR', 'ROLE_BAZ']])

		_fid.roleVoter = new RoleVoter()
		_fid.authenticatedVoter = new AuthenticatedVoter()
		_fid.expressionHandler = new DefaultWebSecurityExpressionHandler()

		assertEquals 0, _fid.configAttributeMap.size()

		_fid.initialize()
		assertEquals 2, _fid.configAttributeMap.size()

		_fid.resetConfigs()

		_fid.initialize()
		assertEquals 0, _fid.configAttributeMap.size()
	}

	void testDetermineUrl() {

		def request = new MockHttpServletRequest()
		def response = new MockHttpServletResponse()
		def chain = new MockFilterChain()
		request.contextPath = '/context'

		request.requestURI = '/context/foo'
		assertEquals '/foo', _fid.determineUrl(new FilterInvocation(request, response, chain))

		request.requestURI = '/context/fOo/Bar?x=1&y=2'
		assertEquals '/foo/bar', _fid.determineUrl(new FilterInvocation(request, response, chain))
	}

	void testSupports() {
		assertTrue _fid.supports(FilterInvocation)
	}

	void testGetAttributes() {
		def request = new MockHttpServletRequest()
		def response = new MockHttpServletResponse()
		def chain = new MockFilterChain()
		FilterInvocation filterInvocation = new FilterInvocation(request, response, chain)

		def matcher = new AntUrlPathMatcher()
		MockInterceptUrlMapFilterInvocationDefinition fid

		def initializeFid = {
			fid = new MockInterceptUrlMapFilterInvocationDefinition()
			fid.urlMatcher = matcher; fid.initialize()
			WebUtils.storeGrailsWebRequest new GrailsWebRequest(request, response, new MockServletContext())
			fid
		}

		def checkConfigAttributeForUrl = {config, String url ->
			request.requestURI = url
			fid.url = url
			assertEquals("Checking config for $url", config, fid.getAttributes(filterInvocation))
		}

		def configAttribute = [new SecurityConfig('ROLE_ADMIN'), new SecurityConfig('ROLE_SUPERUSER')]
		def moreSpecificConfigAttribute = [new SecurityConfig('ROLE_SUPERUSER')]
		fid = initializeFid()
		fid.storeMapping matcher.compile('/secure/**'), configAttribute
		fid.storeMapping matcher.compile('/secure/reallysecure/**'), moreSpecificConfigAttribute
		checkConfigAttributeForUrl(configAttribute, '/secure/reallysecure/list')
		checkConfigAttributeForUrl(configAttribute, '/secure/list')

		fid = initializeFid()
		fid.storeMapping matcher.compile('/secure/reallysecure/**'), moreSpecificConfigAttribute
		fid.storeMapping matcher.compile('/secure/**'), configAttribute
		checkConfigAttributeForUrl(moreSpecificConfigAttribute, '/secure/reallysecure/list')
		checkConfigAttributeForUrl(configAttribute, '/secure/list')

		fid = initializeFid()
		configAttribute = [new SecurityConfig('IS_AUTHENTICATED_FULLY')]
		moreSpecificConfigAttribute = [new SecurityConfig('IS_AUTHENTICATED_ANONYMOUSLY')]
		fid.storeMapping matcher.compile('/unprotected/**'), moreSpecificConfigAttribute
		fid.storeMapping matcher.compile('/**/*.jsp'), configAttribute
		checkConfigAttributeForUrl(moreSpecificConfigAttribute, '/unprotected/b.jsp')
		checkConfigAttributeForUrl(moreSpecificConfigAttribute, '/unprotected/path')
		checkConfigAttributeForUrl(moreSpecificConfigAttribute, '/unprotected/path/x.jsp')
		checkConfigAttributeForUrl(configAttribute, '/b.jsp')
		checkConfigAttributeForUrl(null, '/path')
	}

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#tearDown()
	 */
	@Override
	protected void tearDown() {
		super.tearDown()
		ReflectionUtils.application = null
		SpringSecurityUtils.resetSecurityConfig()
		CH.config = null
	}
}

class MockInterceptUrlMapFilterInvocationDefinition extends InterceptUrlMapFilterInvocationDefinition {
	String url
	protected String findGrailsUrl(UrlMappingInfo mapping) { url }
}
