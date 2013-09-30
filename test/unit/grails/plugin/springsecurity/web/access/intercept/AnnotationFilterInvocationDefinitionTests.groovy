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
import grails.plugin.springsecurity.InterceptedUrl
import grails.web.CamelCaseUrlConverter

import javax.servlet.ServletContext

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
import org.springframework.security.access.annotation.Secured
import org.springframework.security.web.FilterInvocation
import org.springframework.web.context.WebApplicationContext
import org.springframework.web.context.request.RequestContextHolder

/**
 * Unit tests for AnnotationFilterInvocationDefinition.
 *
 * TODO tests method, closure, etc.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class AnnotationFilterInvocationDefinitionTests extends AbstractFilterInvocationDefinitionTests {

	private AnnotationFilterInvocationDefinition fid = new AnnotationFilterInvocationDefinition()

	void testSupports() {
		assertTrue fid.supports(FilterInvocation)
	}

//	void testGetConfigAttributeDefinitions() {
//		assertNull fid.configAttributeDefinitions
//	}

	void testLowercaseAndStripQuerystring() {
		assertEquals '/foo/bar', fid.lowercaseAndStripQuerystring('/foo/BAR')
		assertEquals '/foo/bar', fid.lowercaseAndStripQuerystring('/foo/bar')
		assertEquals '/foo/bar', fid.lowercaseAndStripQuerystring('/foo/BAR?x=1')
	}

	void testGetAttributesNull() {
		shouldFail(IllegalArgumentException) {
			fid.getAttributes null
		}
	}

	void testGetAttributesNotSupports() {
		shouldFail(IllegalArgumentException) {
			fid.getAttributes 'foo'
		}
	}

	void testGetAttributes() {
		def request = new MockHttpServletRequest()
		def response = new MockHttpServletResponse()
		def chain = new MockFilterChain()
		FilterInvocation filterInvocation = new FilterInvocation(request, response, chain)

		fid = new MockAnnotationFilterInvocationDefinition()

		def urlMappingsHolder = [matchAll: { String uri -> [] as UrlMappingInfo[] }] as UrlMappingsHolder
		fid.initialize [:], urlMappingsHolder, [] as GrailsClass[]
		WebUtils.storeGrailsWebRequest new GrailsWebRequest(request, response, new MockServletContext())

		String pattern = '/foo/**'
		def configAttribute = [new SecurityConfig('ROLE_ADMIN')]
		fid.storeMapping pattern, null, configAttribute

		request.requestURI = '/foo/bar'
		fid.url = request.requestURI
		assertEquals configAttribute, fid.getAttributes(filterInvocation)

		fid.rejectIfNoRule = false
		request.requestURI = '/bar/foo'
		fid.url = request.requestURI
		assertNull fid.getAttributes(filterInvocation)

		fid.rejectIfNoRule = true
		assertEquals AbstractFilterInvocationDefinition.DENY, fid.getAttributes(filterInvocation)

		String moreSpecificPattern = '/foo/ba*'
		def moreSpecificConfigAttribute = [new SecurityConfig('ROLE_SUPERADMIN')]
		fid.storeMapping moreSpecificPattern, null, moreSpecificConfigAttribute

		request.requestURI = '/foo/bar'
		fid.url = request.requestURI
		assertEquals moreSpecificConfigAttribute, fid.getAttributes(filterInvocation)
	}

	void testDetermineUrl_StaticRequest() {
		def request = new MockHttpServletRequest()
		def response = new MockHttpServletResponse()
		def filterChain = new MockFilterChain()

		request.requestURI = 'requestURI'

		fid = new MockAnnotationFilterInvocationDefinition()

		def urlMappingsHolder = [matchAll: { String uri -> [] as UrlMappingInfo[] }] as UrlMappingsHolder
		fid.initialize [:], urlMappingsHolder, [] as GrailsClass[]
		WebUtils.storeGrailsWebRequest new GrailsWebRequest(request, response, new MockServletContext())

		FilterInvocation filterInvocation = new FilterInvocation(request, response, filterChain)

		assertEquals 'requesturi', fid.determineUrl(filterInvocation)
	}

	void testDetermineUrl_DynamicRequest() {
		def request = new MockHttpServletRequest()
		def response = new MockHttpServletResponse()
		def filterChain = new MockFilterChain()

		request.requestURI = 'requestURI'

		fid = new MockAnnotationFilterInvocationDefinition(url: 'FOO?x=1', application: application)

		UrlMappingInfo[] mappings = [[getControllerName: { -> 'foo' },
		                              getActionName: { -> 'bar' },
		                              configure: { GrailsWebRequest r -> }] as UrlMappingInfo]
		def urlMappingsHolder = [matchAll: { String uri -> mappings }] as UrlMappingsHolder
		fid.initialize [:], urlMappingsHolder, [] as GrailsClass[]
		WebUtils.storeGrailsWebRequest new GrailsWebRequest(request, response, new MockServletContext())

		FilterInvocation filterInvocation = new FilterInvocation(request, response, filterChain)

		assertEquals 'foo', fid.determineUrl(filterInvocation)
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

		def ctx = initCtx()
		servletContext.setAttribute WebApplicationContext.ROOT_WEB_APPLICATION_CONTEXT_ATTRIBUTE, ctx

		def mappingEvaluator = new DefaultUrlMappingEvaluator(servletContext)

		def urlMappingsHolder = new DefaultUrlMappingsHolder(
				mappings.collect { mappingEvaluator.evaluateMappings(mappings) }.flatten())

		Map<String, Collection<String>> staticRules = ['/js/admin/**': ['ROLE_ADMIN']]
		GrailsClass[] controllerClasses = [new DefaultGrailsControllerClass(ClassAnnotatedController),
		                                   new DefaultGrailsControllerClass(MethodAnnotatedController)]

		fid.roleVoter = ctx.getBean('roleVoter')
		fid.authenticatedVoter = ctx.getBean('authenticatedVoter')
		fid.grailsUrlConverter = new CamelCaseUrlConverter()

		fid.initialize(staticRules, urlMappingsHolder, controllerClasses)

		assertEquals 10, fid.configAttributeMap.size()

		InterceptedUrl iu

		for (key in ['/classannotated', '/classannotated.*', '/classannotated/**']) {
			iu = fid.getInterceptedUrl(key, null)
			assertEquals 1, iu.configAttributes.size()
			assertEquals 'ROLE_ADMIN', iu.configAttributes.iterator().next().attribute
		}

		for (key in ['/classannotated/list', '/classannotated/list.*', '/classannotated/list/**']) {
			iu = fid.getInterceptedUrl(key, null)
			assertEquals 2, iu.configAttributes.size()
			assertEquals(['ROLE_FOO', 'ROLE_SUPERADMIN'] as Set, iu.configAttributes*.attribute as Set)
		}

		for (key in ['/methodannotated/list', '/methodannotated/list.*', '/methodannotated/list/**']) {
			iu = fid.getInterceptedUrl(key, null)
			assertEquals 1, iu.configAttributes.size()
			assertEquals 'ROLE_ADMIN', iu.configAttributes.iterator().next().attribute
		}

		iu = fid.getInterceptedUrl('/js/admin/**', null)
		assertEquals 1, iu.configAttributes.size()
		assertEquals 'ROLE_ADMIN', iu.configAttributes.iterator().next().attribute
	}

//	void testFindConfigAttribute() {
//
//		String pattern = '/foo/**'
//		def configAttribute = [new SecurityConfig('ROLE_ADMIN')]
//		_fid.storeMapping pattern, configAttribute
//
//		assertEquals configAttribute, fid.findConfigAttribute('/foo/bar')
//		assertNull fid.findConfigAttribute('/bar/foo')
//	}

	protected void tearDown() {
		super.tearDown()
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

	def index() {}

	@Secured(['ROLE_SUPERADMIN', 'ROLE_FOO'])
	def list() { [results: []] }
}

class MethodAnnotatedController {

	def index() {}

	@Secured(['ROLE_ADMIN'])
	def list() { [results: []] }
}
