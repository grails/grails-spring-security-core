/* Copyright 2006-2010 the original author or authors.
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

import grails.plugins.springsecurity.Secured

import javax.servlet.ServletContext

import org.codehaus.groovy.grails.commons.DefaultGrailsApplication
import org.codehaus.groovy.grails.commons.DefaultGrailsControllerClass
import org.codehaus.groovy.grails.commons.GrailsApplication
import org.codehaus.groovy.grails.commons.GrailsClass
import org.codehaus.groovy.grails.web.context.ServletContextHolder
import org.codehaus.groovy.grails.web.mapping.DefaultUrlMappingEvaluator
import org.codehaus.groovy.grails.web.mapping.DefaultUrlMappingsHolder
import org.codehaus.groovy.grails.web.mapping.UrlMappingInfo
import org.codehaus.groovy.grails.web.mapping.UrlMappingsHolder
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
import org.springframework.web.context.WebApplicationContext
import org.springframework.web.context.request.RequestContextHolder

/**
 * Unit tests for AnnotationFilterInvocationDefinition.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class AnnotationFilterInvocationDefinitionTests extends GroovyTestCase {

	private _fid
	private final _application = new TestApplication()

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#setUp()
	 */
	@Override
	protected void setUp() {
		super.setUp()
		ReflectionUtils.application = _application
		_fid = new AnnotationFilterInvocationDefinition()
	}

	void testSupports() {
		assertTrue _fid.supports(FilterInvocation)
	}

//	void testGetConfigAttributeDefinitions() {
//		assertNull _fid.configAttributeDefinitions
//	}

	void testLowercaseAndStripQuerystring() {
		_fid.urlMatcher = new AntUrlPathMatcher()

		assertEquals '/foo/bar', _fid.lowercaseAndStripQuerystring('/foo/BAR')
		assertEquals '/foo/bar', _fid.lowercaseAndStripQuerystring('/foo/bar')
		assertEquals '/foo/bar', _fid.lowercaseAndStripQuerystring('/foo/BAR?x=1')
	}

	void testGetAttributesNull() {
		shouldFail(IllegalArgumentException) {
			_fid.getAttributes null
		}
	}

	void testGetAttributesNotSupports() {
		shouldFail(IllegalArgumentException) {
			_fid.getAttributes 'foo'
		}
	}

	void testGetAttributes() {
		def request = new MockHttpServletRequest()
		def response = new MockHttpServletResponse()
		def chain = new MockFilterChain()
		FilterInvocation filterInvocation = new FilterInvocation(request, response, chain)

		def matcher = new AntUrlPathMatcher()

		_fid = new MockAnnotationFilterInvocationDefinition()
		_fid.urlMatcher = matcher

		def urlMappingsHolder = [matchAll: { String uri -> [] as UrlMappingInfo[] }] as UrlMappingsHolder
		_fid.initialize [:], urlMappingsHolder, [] as GrailsClass[]
		WebUtils.storeGrailsWebRequest new GrailsWebRequest(request, response, new MockServletContext())

		String pattern = '/foo/**'
		def configAttribute = [new SecurityConfig('ROLE_ADMIN')]
		_fid.storeMapping matcher.compile(pattern), configAttribute

		request.requestURI = '/foo/bar'
		_fid.url = request.requestURI
		assertEquals configAttribute, _fid.getAttributes(filterInvocation)

		_fid.rejectIfNoRule = false
		request.requestURI = '/bar/foo'
		_fid.url = request.requestURI
		assertNull _fid.getAttributes(filterInvocation)

		_fid.rejectIfNoRule = true
		assertEquals AbstractFilterInvocationDefinition.DENY, _fid.getAttributes(filterInvocation)

		String moreSpecificPattern = '/foo/ba*'
		def moreSpecificConfigAttribute = [new SecurityConfig('ROLE_SUPERADMIN')]
		_fid.storeMapping matcher.compile(moreSpecificPattern), moreSpecificConfigAttribute

		request.requestURI = '/foo/bar'
		_fid.url = request.requestURI
		assertEquals moreSpecificConfigAttribute, _fid.getAttributes(filterInvocation)
	}

	void testDetermineUrl_StaticRequest() {
		def request = new MockHttpServletRequest()
		def response = new MockHttpServletResponse()
		def filterChain = new MockFilterChain()

		request.requestURI = 'requestURI'

		_fid = new MockAnnotationFilterInvocationDefinition()
		_fid.urlMatcher = new AntUrlPathMatcher()

		def urlMappingsHolder = [matchAll: { String uri -> [] as UrlMappingInfo[] }] as UrlMappingsHolder
		_fid.initialize [:], urlMappingsHolder, [] as GrailsClass[]
		WebUtils.storeGrailsWebRequest new GrailsWebRequest(request, response, new MockServletContext())

		FilterInvocation filterInvocation = new FilterInvocation(request, response, filterChain)

		assertEquals 'requesturi', _fid.determineUrl(filterInvocation)
	}

	void testDetermineUrl_DynamicRequest() {
		def request = new MockHttpServletRequest()
		def response = new MockHttpServletResponse()
		def filterChain = new MockFilterChain()

		request.requestURI = 'requestURI'

		_fid = new MockAnnotationFilterInvocationDefinition(
			url: 'FOO?x=1', application: _application,
			urlMatcher: new AntUrlPathMatcher())

		UrlMappingInfo[] mappings = [[getControllerName: { -> 'foo' },
		                              getActionName: { -> 'bar' },
		                              configure: { GrailsWebRequest r -> }] as UrlMappingInfo]
		def urlMappingsHolder = [matchAll: { String uri -> mappings }] as UrlMappingsHolder
		_fid.initialize [:], urlMappingsHolder, [] as GrailsClass[]
		WebUtils.storeGrailsWebRequest new GrailsWebRequest(request, response, new MockServletContext())

		FilterInvocation filterInvocation = new FilterInvocation(request, response, filterChain)

		assertEquals 'foo', _fid.determineUrl(filterInvocation)
	}

	void testInitialize() {

		def mappings = {

			"/admin/user/$action?/$id?"(controller: "adminUser")

			"/$controller/$action?/$id?" { constraints {} }

			"/"(view:"/index")

			/**** Error Mappings ****/

			"403"(controller: "errors", action: "accessDenied")
			"404"(controller: "errors", action: "notFound")
			"405"(controller: "errors", action: "notAllowed")
			"500"(view: '/error')
		}

		ServletContext servletContext = new MockServletContext()

		def app = new DefaultGrailsApplication()
		def beans = [(GrailsApplication.APPLICATION_ID): app]
		def ctx = [getBean: { String name -> beans[name] }] as WebApplicationContext
		servletContext.setAttribute WebApplicationContext.ROOT_WEB_APPLICATION_CONTEXT_ATTRIBUTE, ctx

		def mappingEvaluator = new DefaultUrlMappingEvaluator(servletContext)

		def urlMappingsHolder = new DefaultUrlMappingsHolder(
				mappings.collect { mappingEvaluator.evaluateMappings(mappings) }.flatten())

		Map<String, Collection<String>> staticRules = ['/js/admin/**': ['ROLE_ADMIN']]
		GrailsClass[] controllerClasses = [new DefaultGrailsControllerClass(ClassAnnotatedController),
		                                   new DefaultGrailsControllerClass(MethodAnnotatedController)]

		_fid.urlMatcher = new AntUrlPathMatcher()
		_fid.roleVoter = new RoleVoter()
		_fid.authenticatedVoter = new AuthenticatedVoter()
		_fid.expressionHandler = new DefaultWebSecurityExpressionHandler()

		_fid.initialize(staticRules, urlMappingsHolder, controllerClasses)

		assertEquals 4, _fid.configAttributeMap.size()

		def configAttributes

		configAttributes = _fid.configAttributeMap['/classannotated/**']
		assertEquals 1, configAttributes.size()
		assertEquals 'ROLE_ADMIN', configAttributes.iterator().next().attribute

		configAttributes = _fid.configAttributeMap['/classannotated/list/**']
		assertEquals 2, configAttributes.size()
		assertEquals(['ROLE_FOO', 'ROLE_SUPERADMIN'] as Set, configAttributes*.attribute as Set)

		configAttributes = _fid.configAttributeMap['/methodannotated/list/**']
		assertEquals 1, configAttributes.size()
		assertEquals 'ROLE_ADMIN', configAttributes.iterator().next().attribute

		configAttributes = _fid.configAttributeMap['/js/admin/**']
		assertEquals 1, configAttributes.size()
		assertEquals 'ROLE_ADMIN', configAttributes.iterator().next().attribute
	}

//	void testFindConfigAttribute() {
//
//		def matcher = new AntUrlPathMatcher()
//
//		_fid.urlMatcher = matcher
//
//		String pattern = '/foo/**'
//		def configAttribute = [new SecurityConfig('ROLE_ADMIN')]
//		_fid.storeMapping matcher.compile(pattern), configAttribute
//
//		assertEquals configAttribute, _fid.findConfigAttribute('/foo/bar')
//		assertNull _fid.findConfigAttribute('/bar/foo')
//	}

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#tearDown()
	 */
	@Override
	protected void tearDown() {
		super.tearDown()
		ReflectionUtils.application = null
		RequestContextHolder.resetRequestAttributes()
		ServletContextHolder.servletContext = null
	}
}

class TestApplication extends FakeApplication {
	GrailsClass getArtefactForFeature(String artefactType, Object featureID) { [:] as GrailsClass }
}

class MockAnnotationFilterInvocationDefinition extends AnnotationFilterInvocationDefinition {
	String url
	protected String findGrailsUrl(UrlMappingInfo mapping) { url }
}

@Secured(['ROLE_ADMIN'])
class ClassAnnotatedController {

	def index = {}

	@Secured(['ROLE_SUPERADMIN', 'ROLE_FOO'])
	def list = { [results: []] }
}

class MethodAnnotatedController {

	def index = {}

	@Secured(['ROLE_ADMIN'])
	def list = { [results: []] }
}
