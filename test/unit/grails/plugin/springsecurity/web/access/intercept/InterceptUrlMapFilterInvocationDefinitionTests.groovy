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
package grails.plugin.springsecurity.web.access.intercept

import grails.plugin.springsecurity.InterceptedUrl
import grails.plugin.springsecurity.ReflectionUtils
import grails.plugin.springsecurity.SpringSecurityUtils

import org.codehaus.groovy.grails.web.mapping.UrlMappingInfo
import org.codehaus.groovy.grails.web.servlet.mvc.GrailsWebRequest
import org.codehaus.groovy.grails.web.util.WebUtils
import org.springframework.http.HttpMethod
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.mock.web.MockServletContext
import org.springframework.security.access.ConfigAttribute
import org.springframework.security.access.SecurityConfig
import org.springframework.security.access.vote.AuthenticatedVoter
import org.springframework.security.access.vote.RoleVoter
import org.springframework.security.web.FilterInvocation

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class InterceptUrlMapFilterInvocationDefinitionTests extends AbstractFilterInvocationDefinitionTests {

	private InterceptUrlMapFilterInvocationDefinition fid = new InterceptUrlMapFilterInvocationDefinition()

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#setUp()
	 */
	@Override
	protected void setUp() {
		super.setUp()
		ReflectionUtils.application = application
	}

	void testStoreMapping() {

		assertEquals 0, fid.configAttributeMap.size()

		fid.storeMapping '/foo/bar', null, ['ROLE_ADMIN']
		assertEquals 1, fid.configAttributeMap.size()

		fid.storeMapping '/foo/bar', null, ['ROLE_USER']
		assertEquals 1, fid.configAttributeMap.size()

		fid.storeMapping '/other/path', null, ['ROLE_SUPERUSER']
		assertEquals 2, fid.configAttributeMap.size()
	}

	void testInitialize() {
		ReflectionUtils.setConfigProperty('interceptUrlMap',
				['/foo/**': 'ROLE_ADMIN',
				 '/bar/**': ['ROLE_BAR', 'ROLE_BAZ']])

		def ctx = initCtx()

		fid.roleVoter = ctx.getBean('roleVoter')
		fid.authenticatedVoter = ctx.getBean('authenticatedVoter')

		assertEquals 0, fid.configAttributeMap.size()

		fid.initialize()
		assertEquals 2, fid.configAttributeMap.size()

		fid.resetConfigs()

		fid.initialize()
		assertEquals 0, fid.configAttributeMap.size()
	}

	void te2stInitializeWithNewSyntax() {
		ReflectionUtils.setConfigProperty('interceptUrlMap',
				[[pattern: '/foo/**', access: 'ROLE_ADMIN', httpMethod: HttpMethod.POST],
				 [pattern: '/bar/**', access: ['ROLE_BAR', 'ROLE_BAZ']]])

		fid.roleVoter = new RoleVoter()
		fid.authenticatedVoter = new AuthenticatedVoter()
//		fid.expressionHandler = new DefaultWebSecurityExpressionHandler()

		assertEquals 0, fid.configAttributeMap.size()

		fid.initialize()
		assertEquals 2, fid.configAttributeMap.size()

		def attributes = fid.configAttributeMap[new InterceptedUrl()]

		fid.resetConfigs()

		fid.initialize()
		assertEquals 0, fid.configAttributeMap.size()
	}

	void testDetermineUrl() {

		def request = new MockHttpServletRequest()
		def response = new MockHttpServletResponse()
		def chain = new MockFilterChain()
		request.contextPath = '/context'

		request.requestURI = '/context/foo'
		assertEquals '/foo', fid.determineUrl(new FilterInvocation(request, response, chain))

		request.requestURI = '/context/fOo/Bar?x=1&y=2'
		assertEquals '/foo/bar', fid.determineUrl(new FilterInvocation(request, response, chain))
	}

	void testSupports() {
		assertTrue fid.supports(FilterInvocation)
	}

	void testGetAttributes() {
		def request = new MockHttpServletRequest()
		def response = new MockHttpServletResponse()
		def chain = new MockFilterChain()
		FilterInvocation filterInvocation = new FilterInvocation(request, response, chain)

		MockInterceptUrlMapFilterInvocationDefinition fid

		def initializeFid = {
			fid = new MockInterceptUrlMapFilterInvocationDefinition()
			fid.initialize()
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
		fid.storeMapping '/secure/**', null, configAttribute
		fid.storeMapping '/secure/reallysecure/**', null, moreSpecificConfigAttribute
		checkConfigAttributeForUrl(configAttribute, '/secure/reallysecure/list')
		checkConfigAttributeForUrl(configAttribute, '/secure/list')

		fid = initializeFid()
		fid.storeMapping '/secure/reallysecure/**', null, moreSpecificConfigAttribute
		fid.storeMapping '/secure/**', null, configAttribute
		checkConfigAttributeForUrl(moreSpecificConfigAttribute, '/secure/reallysecure/list')
		checkConfigAttributeForUrl(configAttribute, '/secure/list')

		fid = initializeFid()
		configAttribute = [new SecurityConfig('IS_AUTHENTICATED_FULLY')]
		moreSpecificConfigAttribute = [new SecurityConfig('IS_AUTHENTICATED_ANONYMOUSLY')]
		fid.storeMapping '/unprotected/**', null, moreSpecificConfigAttribute
		fid.storeMapping '/**/*.jsp', null, configAttribute
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
		org.codehaus.groovy.grails.commons.ConfigurationHolder.config = null
	}
}

class MockInterceptUrlMapFilterInvocationDefinition extends InterceptUrlMapFilterInvocationDefinition {
	String url
	protected String findGrailsUrl(UrlMappingInfo mapping) { url }
}
