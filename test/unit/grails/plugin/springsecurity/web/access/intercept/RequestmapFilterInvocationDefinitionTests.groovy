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

import grails.plugin.springsecurity.FakeApplication
import grails.plugin.springsecurity.ReflectionUtils
import grails.plugin.springsecurity.SpringSecurityUtils
import grails.test.GrailsUnitTestCase

import org.codehaus.groovy.grails.commons.ConfigurationHolder as CH
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.access.vote.AuthenticatedVoter
import org.springframework.security.access.vote.RoleVoter
import org.springframework.security.web.FilterInvocation
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler
import org.springframework.security.web.util.AntUrlPathMatcher

/**
 * Unit tests for RequestmapFilterInvocationDefinition.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class RequestmapFilterInvocationDefinitionTests extends GrailsUnitTestCase {

	private RequestmapFilterInvocationDefinition _fid = new RequestmapFilterInvocationDefinition()
	private final FakeApplication _application = new FakeApplication()

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#setUp()
	 */
	@Override
	protected void setUp() {
		super.setUp()
//		_application.addToLoaded(TestRequestmap)
		ReflectionUtils.application = _application
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

	void testSplit() {
		assertEquals(['ROLE_1', 'ROLE_2', 'ROLE_3', 'ROLE_4', 'ROLE_5'], _fid.split('ROLE_1, ROLE_2,,,ROLE_3 ,ROLE_4,ROLE_5'))
		assertEquals(['hasAnyRole("ROLE_1","ROLE_2")'], _fid.split('hasAnyRole("ROLE_1","ROLE_2")'))
	}

//	void testLoadRequestmaps() {
//		def requestMapConfig = SpringSecurityUtils.securityConfig.requestMap
//		requestMapConfig.className = TestRequestmap.name
//		requestMapConfig.urlField = 'urlPattern'
//		requestMapConfig.configAttributeField = 'rolePattern'
//
//		def instances = [new TestRequestmap(urlPattern: 'path1', rolePattern: 'config1'),
//		                 new TestRequestmap(urlPattern: 'path2', rolePattern: 'config2'),
//		                 new TestRequestmap(urlPattern: 'path3', rolePattern: 'config3')]
//		mockDomain TestRequestmap, instances
//
//		def requestmaps = _fid.loadRequestmaps()
//		assertEquals 3, requestmaps.size()
//		assertEquals 'config1', requestmaps.path1
//		assertEquals 'config2', requestmaps.path2
//		assertEquals 'config3', requestmaps.path3
//	}

	void testAfterPropertiesSet() {
		assertEquals 'url matcher is required', shouldFail(IllegalArgumentException) {
			_fid.afterPropertiesSet()
		}

		_fid.urlMatcher = new AntUrlPathMatcher()

		_fid.afterPropertiesSet()
	}

	void testStoreMapping() {
		_fid.urlMatcher = new AntUrlPathMatcher()

		assertEquals 0, _fid.configAttributeMap.size()

		_fid.storeMapping '/foo/bar', ['ROLE_ADMIN']
		assertEquals 1, _fid.configAttributeMap.size()

		_fid.storeMapping '/foo/bar', ['ROLE_USER']
		assertEquals 1, _fid.configAttributeMap.size()

		_fid.storeMapping '/other/path', ['ROLE_SUPERUSER']
		assertEquals 2, _fid.configAttributeMap.size()
	}

	void testReset() {
		_fid = new TestRequestmapFilterInvocationDefinition()
		_fid.urlMatcher = new AntUrlPathMatcher()
		_fid.roleVoter = new RoleVoter()
		_fid.authenticatedVoter = new AuthenticatedVoter()
		_fid.expressionHandler = new DefaultWebSecurityExpressionHandler()

		assertEquals 0, _fid.configAttributeMap.size()

		_fid.reset()

		assertEquals 2, _fid.configAttributeMap.size()
	}

	void testInitialize() {
		_fid = new TestRequestmapFilterInvocationDefinition()
		_fid.urlMatcher = new AntUrlPathMatcher()
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
		_fid.urlMatcher = new AntUrlPathMatcher()

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
}

class TestRequestmapFilterInvocationDefinition extends RequestmapFilterInvocationDefinition {
	protected Map<String, String> loadRequestmaps() {
		['/foo/bar': 'ROLE_USER', '/admin/**': 'ROLE_ADMIN']
	}
}
