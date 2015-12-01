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
package grails.plugin.springsecurity.web.access.intercept

import grails.plugin.springsecurity.FakeApplication
import grails.plugin.springsecurity.InterceptedUrl
import grails.plugin.springsecurity.access.vote.ClosureConfigAttribute
import grails.plugin.springsecurity.annotation.Secured
import grails.web.CamelCaseUrlConverter

import javax.servlet.ServletContext

import org.codehaus.groovy.grails.commons.DefaultGrailsControllerClass
import org.codehaus.groovy.grails.commons.GrailsClass
import org.codehaus.groovy.grails.web.mapping.DefaultUrlMappingEvaluator
import org.codehaus.groovy.grails.web.mapping.DefaultUrlMappingsHolder
import org.codehaus.groovy.grails.web.mapping.UrlMappingInfo
import org.codehaus.groovy.grails.web.mapping.UrlMappingsHolder
import org.codehaus.groovy.grails.web.servlet.mvc.GrailsWebRequest
import org.codehaus.groovy.grails.web.util.WebUtils
import org.springframework.http.HttpMethod
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.mock.web.MockServletContext
import org.springframework.security.access.SecurityConfig
import org.springframework.security.web.FilterInvocation
import org.springframework.web.context.WebApplicationContext
import org.springframework.web.context.request.RequestContextHolder

/**
 * Unit tests for AnnotationFilterInvocationDefinition.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class AnnotationFilterInvocationDefinitionTests extends AbstractFilterInvocationDefinitionTests {

	private AnnotationFilterInvocationDefinition fid = new AnnotationFilterInvocationDefinition()

	void testSupports() {
		assert fid.supports(FilterInvocation)
	}

//	void testGetConfigAttributeDefinitions() {
//		assert !fid.configAttributeDefinitions
//	}

	void testLowercaseAndStripQuerystring() {
		assert '/foo/bar' == fid.lowercaseAndStripQuerystring('/foo/BAR')
		assert '/foo/bar' == fid.lowercaseAndStripQuerystring('/foo/bar')
		assert '/foo/bar' == fid.lowercaseAndStripQuerystring('/foo/BAR?x=1')
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
		assert configAttribute == fid.getAttributes(filterInvocation)

		fid.rejectIfNoRule = false
		request.requestURI = '/bar/foo'
		fid.url = request.requestURI
		assert !fid.getAttributes(filterInvocation)

		fid.rejectIfNoRule = true
		assert AbstractFilterInvocationDefinition.DENY == fid.getAttributes(filterInvocation)

		String moreSpecificPattern = '/foo/ba*'
		def moreSpecificConfigAttribute = [new SecurityConfig('ROLE_SUPERADMIN')]
		fid.storeMapping moreSpecificPattern, null, moreSpecificConfigAttribute

		request.requestURI = '/foo/bar'
		fid.url = request.requestURI
		assert moreSpecificConfigAttribute == fid.getAttributes(filterInvocation)
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

		assert 'requesturi' == fid.determineUrl(filterInvocation)
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

		assert 'foo' == fid.determineUrl(filterInvocation)
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

		assert 16 == fid.configAttributeMap.size()

		InterceptedUrl iu

		for (key in ['/classannotated', '/classannotated.*', '/classannotated/**']) {
			iu = fid.getInterceptedUrl(key, null)
			assert 1 == iu.configAttributes.size()
			assert 'ROLE_ADMIN' == iu.configAttributes.iterator().next().attribute
			assert !iu.httpMethod
		}

		for (key in ['/classannotated/list', '/classannotated/list.*', '/classannotated/list/**']) {
			iu = fid.getInterceptedUrl(key, null)
			assert 2 == iu.configAttributes.size()
			assert ['ROLE_FOO', 'ROLE_SUPERADMIN'] as Set == iu.configAttributes*.attribute as Set
			assert !iu.httpMethod
		}

		for (key in ['/methodannotated/list', '/methodannotated/list.*', '/methodannotated/list/**']) {
			iu = fid.getInterceptedUrl(key, null)
			assert 1 == iu.configAttributes.size()
			assert 'ROLE_ADMIN' == iu.configAttributes.iterator().next().attribute
			assert !iu.httpMethod
		}

		for (key in ['/methodannotated/bar', '/methodannotated/bar.*', '/methodannotated/bar/**']) {
			iu = fid.getInterceptedUrl(key, HttpMethod.PUT)
			assert 1 == iu.configAttributes.size()
			assert 'ROLE_ADMIN' == iu.configAttributes.iterator().next().attribute
			assert HttpMethod.PUT == iu.httpMethod
		}

		for (key in ['/methodannotated/foo', '/methodannotated/foo.*', '/methodannotated/foo/**']) {
			iu = fid.getInterceptedUrl(key, null)
			assert 1 == iu.configAttributes.size()
			assert iu.configAttributes.iterator().next() instanceof ClosureConfigAttribute
			assert !iu.httpMethod
		}

		iu = fid.getInterceptedUrl('/js/admin/**', null)
		assert 1 == iu.configAttributes.size()
		assert 'ROLE_ADMIN' == iu.configAttributes.iterator().next().attribute
	}

//	void testFindConfigAttribute() {
//
//		String pattern = '/foo/**'
//		def configAttribute = [new SecurityConfig('ROLE_ADMIN')]
//		_fid.storeMapping pattern, configAttribute
//
//		assert configAttribute == fid.findConfigAttribute('/foo/bar')
//		assert !fid.findConfigAttribute('/bar/foo')
//	}

	protected void tearDown() {
		super.tearDown()
		RequestContextHolder.resetRequestAttributes()
	}
}

class TestApplication extends FakeApplication {
	GrailsClass getArtefactForFeature(String artefactType, featureID) { [:] as GrailsClass }
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

	@Secured(closure = {
		assert request
		assert ctx
		authentication.name == 'admin1'
	})
	def foo() { [results: []] }

	@Secured(value=['ROLE_ADMIN'], httpMethod='PUT')
	def bar() { [results: []] }
}
