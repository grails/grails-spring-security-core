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

import java.lang.annotation.Annotation
import java.lang.reflect.AccessibleObject
import java.lang.reflect.Constructor
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Method

import javax.servlet.ServletContext
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

import org.grails.core.artefact.ControllerArtefactHandler
import org.grails.web.mime.HttpServletResponseExtension
import org.grails.web.servlet.mvc.GrailsWebRequest
import org.grails.web.util.WebUtils
import org.springframework.http.HttpMethod
import org.springframework.security.access.ConfigAttribute
import org.springframework.security.web.FilterInvocation
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource
import org.springframework.util.ReflectionUtils
import org.springframework.util.StringUtils
import org.springframework.web.context.ServletContextAware

import grails.core.GrailsApplication
import grails.core.GrailsClass
import grails.core.GrailsControllerClass
import grails.plugin.springsecurity.InterceptedUrl
import grails.plugin.springsecurity.access.vote.ClosureConfigAttribute
import grails.web.UrlConverter
import grails.web.mapping.UrlMappingInfo
import grails.web.mapping.UrlMappingsHolder
import grails.web.servlet.mvc.GrailsParameterMap
import groovy.transform.CompileStatic

/**
 * A {@link FilterInvocationSecurityMetadataSource} that uses rules defined with
 * Controller annotations combined with static rules defined in
 * <code>SecurityConfig.groovy</code>, e.g. for js, images, css or for rules
 * that cannot be expressed in a controller like '/**'.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
@CompileStatic
class AnnotationFilterInvocationDefinition extends AbstractFilterInvocationDefinition implements ServletContextAware {

	protected static String SLASH = '/'

	protected UrlMappingsHolder urlMappingsHolder

	ServletContext servletContext

	/** Dependency injection for the application. */
	GrailsApplication application

	/** Dependency injection for the httpServletResponseExtension bean. */
	HttpServletResponseExtension httpServletResponseExtension

	/** Dependency injection for the grailsUrlConverter bean. */
	UrlConverter grailsUrlConverter

	@Override
	protected String determineUrl(FilterInvocation filterInvocation) {
		HttpServletRequest request = filterInvocation.httpRequest
		HttpServletResponse response = filterInvocation.httpResponse

		GrailsWebRequest existingRequest
		try {
			existingRequest = WebUtils.retrieveGrailsWebRequest()
		}
		catch (IllegalStateException e) {
			throw new IllegalStateException(
				'There was a problem retrieving the current GrailsWebRequest. This usually indicates a filter ordering ' +
				"issue in web.xml (the 'springSecurityFilterChain' filter-mapping element must be positioned after the " +
				"'grailsWebRequest' element when using @Secured annotations) but this should be handled correctly by the " +
				'webxml plugin. Ensure that the webxml plugin is installed (it should be transitively installed as a ' +
				'dependency of the spring-security-core plugin)')
		}

		String requestUrl = calculateUri(request)

		log.trace 'Requested url: {}', requestUrl

		String url
		try {
			GrailsWebRequest grailsRequest = new GrailsWebRequest(request, response, servletContext)
			WebUtils.storeGrailsWebRequest grailsRequest

			Map<String, Object> savedParams = copyParams(grailsRequest)

			UrlMappingInfo[] urlInfos = grails.plugin.springsecurity.ReflectionUtils.matchAllUrlMappings(
					urlMappingsHolder, requestUrl, grailsRequest, httpServletResponseExtension)

			for (UrlMappingInfo mapping : urlInfos) {
				if (grails.plugin.springsecurity.ReflectionUtils.isRedirect(mapping)) {
					log.trace 'Mapping {} is a redirect', mapping
					break
				}

				configureMapping mapping, grailsRequest, savedParams

				url = findGrailsUrl(mapping)
				if (url) {
					break
				}
			}
		}
		finally {
			if (existingRequest) {
				WebUtils.storeGrailsWebRequest(existingRequest)
			}
			else {
				WebUtils.clearGrailsWebRequest()
			}
		}

		if (!StringUtils.hasLength(url)) {
			// probably css/js/image
			url = requestUrl
		}

		String finalUrl = lowercaseAndStripQuerystring(url)
		log.trace 'Final url is {}', finalUrl
		finalUrl
	}

	protected String findGrailsUrl(UrlMappingInfo mapping) {

		String uri = mapping.URI
		if (uri) {
			return uri
		}

		String viewName = mapping.viewName
		if (viewName != null) {
			if (!viewName.startsWith(SLASH)) {
				viewName = SLASH + viewName
			}
			return viewName
		}

		String actionName = mapping.actionName ?: ''
		String controllerName = mapping.controllerName

		if (isController(controllerName, actionName)) {
			return createControllerUri(controllerName, actionName)
		}

		if (controllerName != null) {
			String namespace = mapping.namespace
			if (namespace != null) {
				String fullControllerName = resolveFullControllerName(controllerName, namespace)
				return createControllerUri(fullControllerName, actionName)
			}
		}
	}

	protected String createControllerUri(String controllerName, String actionName) {
		if (!actionName || 'null' == actionName) {
			actionName = 'index'
		}
		(SLASH + controllerName + SLASH + actionName).trim()
	}

	protected boolean isController(String controllerName, String actionName) {
		application.getArtefactForFeature(ControllerArtefactHandler.TYPE, SLASH + controllerName + SLASH + actionName)
	}

	protected void configureMapping(UrlMappingInfo mapping, GrailsWebRequest grailsRequest, Map<String, Object> savedParams) {

		// reset params since mapping.configure() sets values
		GrailsParameterMap params = grailsRequest.params
		params.clear()
		params << savedParams

		mapping.configure grailsRequest
	}

	@SuppressWarnings('unchecked')
	protected Map<String, Object> copyParams(GrailsWebRequest grailsRequest) {
		[:] << grailsRequest.params
	}

	/**
	 * Called by the plugin to set controller role info.<br>
	 *
	 * Reinitialize by calling <code>ctx.objectDefinitionSource.initialize(
	 * 	ctx.authenticateService.securityConfig.security.annotationStaticRules,
	 * 	ctx.grailsUrlMappingsHolder,
	 * 	grailsApplication.controllerClasses)</code>
	 *
	 * @param staticRules data from the controllerAnnotations.staticRules config attribute
	 * @param mappingsHolder mapping holder
	 * @param controllerClasses all controllers
	 */
	void initialize(staticRules, UrlMappingsHolder mappingsHolder, GrailsClass[] controllerClasses) {

		assert staticRules != null, 'staticRules map is required'
		assert mappingsHolder, 'urlMappingsHolder is required'

		resetConfigs()

		urlMappingsHolder = mappingsHolder

		Map<String, List<InterceptedUrl>> actionRoleMap = [:]
		List<InterceptedUrl> classRoleMap = []
		Map<String, List<InterceptedUrl>> actionClosureMap = [:]
		List<InterceptedUrl> classClosureMap = []

		for (GrailsClass controllerClass in controllerClasses) {
			findControllerAnnotations((GrailsControllerClass)controllerClass, actionRoleMap, classRoleMap, actionClosureMap, classClosureMap)
		}

		compileStaticRules staticRules
		compileActionClosureMap actionClosureMap
		compileClassClosureMap classClosureMap
		compileActionMap actionRoleMap
		compileClassMap classRoleMap

		if (log.traceEnabled) {
			log.trace 'configs: {}', configAttributeMap
		}
	}

	protected void compileActionMap(Map<String, List<InterceptedUrl>> map) {
		map.each { String controllerName, List<InterceptedUrl> urls ->
			for (InterceptedUrl iu in urls) {
				Collection<ConfigAttribute> configAttributes = iu.configAttributes
				String actionName = iu.pattern
				HttpMethod method = iu.httpMethod
				storeMapping controllerName, actionName, configAttributes, false, method
				if (actionName.endsWith('Flow')) {
					// WebFlow actions end in Flow but are accessed without the suffix, so guard both
					storeMapping controllerName, actionName.substring(0, actionName.length() - 4), configAttributes, false, method
				}
			}
		}
	}

	protected void compileActionClosureMap(Map<String, List<InterceptedUrl>> map) {
		map.each { String controllerName, List<InterceptedUrl> actionClosures ->
			for (InterceptedUrl iu in actionClosures) {
				String actionName = iu.pattern
				Class<?> closureClass = iu.closureClass
				HttpMethod method = iu.httpMethod
				storeMapping controllerName, actionName, closureClass, method
				if (actionName.endsWith('Flow')) {
					// WebFlow actions end in Flow but are accessed without the suffix, so guard both
					storeMapping controllerName, actionName.substring(0, actionName.length() - 4), closureClass, method
				}
			}
		}
	}

	protected void compileClassMap(List<InterceptedUrl> classRoleMap) {
		classRoleMap.each { InterceptedUrl iu ->
			storeMapping iu.pattern, null, iu.configAttributes, false, iu.httpMethod
		}
	}

	protected void compileClassClosureMap(List<InterceptedUrl> classClosureMap) {
		classClosureMap.each { InterceptedUrl iu ->
			storeMapping iu.pattern, null, iu.closureClass, iu.httpMethod
		}
	}

	protected Closure<?> newInstance(Class<?> closureClass) {
		try {
			Constructor<?> constructor = closureClass.getConstructor(Object, Object)
			ReflectionUtils.makeAccessible constructor
			(Closure<?>) constructor.newInstance(this, this)
		}
		catch (NoSuchMethodException | InstantiationException | IllegalAccessException e) {
			ReflectionUtils.handleReflectionException e
		}
		catch (InvocationTargetException e) {
			ReflectionUtils.handleInvocationTargetException e
		}
	}

	@SuppressWarnings('unchecked')
	protected void compileStaticRules(staticRules) {
		List<InterceptedUrl> rules
		if (staticRules instanceof Map) {
			rules = grails.plugin.springsecurity.ReflectionUtils.splitMap((Map<String, Object>)staticRules)
		}
		else if (staticRules instanceof List) {
			rules = grails.plugin.springsecurity.ReflectionUtils.splitMap((List<Map<String, Object>>)staticRules)
		}
		else {
			return
		}

		rules.each { InterceptedUrl iu ->
			storeMapping iu.pattern, null, iu.configAttributes, true, iu.httpMethod
		}
	}

	protected void storeMapping(String controllerNameOrPattern, String actionName,
	                            Collection<ConfigAttribute> configAttributes, boolean isPattern, HttpMethod method) {

		generatePatterns(controllerNameOrPattern, actionName, isPattern).each { String pattern ->
			doStoreMapping pattern, method, configAttributes
		}
	}

	protected void storeMapping(String controllerName, String actionName, Class<?> closureClass, HttpMethod method) {
		if (closureClass == grails.plugin.springsecurity.annotation.Secured) {
			return
		}

		generatePatterns(controllerName, actionName, false).each { String pattern ->
			Collection<ConfigAttribute> configAttributes = [new ClosureConfigAttribute(newInstance(closureClass))] as Collection

			String key = pattern.toLowerCase()
			InterceptedUrl replaced = storeMapping(key, method, configAttributes)
			if (replaced) {
				log.warn "replaced rule for '{}' with tokens {} with tokens {}",
						  [key, replaced.configAttributes, configAttributes] as Object[]
			}
		}
	}

	protected List<String> generatePatterns(String controllerNameOrPattern, String actionName, boolean isPattern) {

		if (isPattern) {
			return [controllerNameOrPattern]
		}

		StringBuilder sb = new StringBuilder()
		sb << '/' << controllerNameOrPattern
		if (actionName != null) {
			sb << '/' << actionName
		}
		List<String> patterns = [sb.toString(), sb.toString() + '.*'] // TODO

		sb << '/**'
		patterns << sb.toString()

		patterns
	}

	protected void doStoreMapping(String fullPattern, HttpMethod method, Collection<ConfigAttribute> configAttributes) {
		String key = fullPattern.toString().toLowerCase()
		InterceptedUrl replaced = storeMapping(key, method, configAttributes)
		if (replaced) {
			log.warn "Replaced rule for '{}' and ConfigAttributes {} with ConfigAttributes {}", [key, replaced.configAttributes, configAttributes] as Object[]
		}
		else {
			log.trace "Storing ConfigAttributes {} for '{}' and HttpMethod {}", [key, configAttributes, method] as Object[]
		}
	}

	protected void findControllerAnnotations(
			GrailsControllerClass controllerClass,
			Map<String, List<InterceptedUrl>> actionRoleMap,
			List<InterceptedUrl> classRoleMap,
			Map<String, List<InterceptedUrl>> actionClosureMap,
			List<InterceptedUrl> classClosureMap) {

		Class<?> clazz = controllerClass.clazz
		String controllerName = resolveFullControllerName(controllerClass)

		Annotation annotation = clazz.getAnnotation(org.springframework.security.access.annotation.Secured)
		if (!annotation) {
			annotation = clazz.getAnnotation(grails.plugin.springsecurity.annotation.Secured)
			if (annotation) {
				Class<?> closureClass = findClosureClass((grails.plugin.springsecurity.annotation.Secured)annotation)
				if (!closureClass) {
					Collection<String> values = getValue(annotation)
					log.trace 'found class-scope annotation in {} with value(s) {}', clazz.name, values
					classRoleMap << new InterceptedUrl(controllerName, values, getHttpMethod(annotation))
				}
				else {
					log.trace 'found class-scope annotation with a closure in {}', clazz.name
					classClosureMap << new InterceptedUrl(controllerName, closureClass, getHttpMethod(annotation))
				}
			}
		}
		else {
			Collection<String> values = getValue(annotation)
			log.trace 'found class-scope annotation in {} with value(s) {}', clazz.name, values
			classRoleMap << new InterceptedUrl(controllerName, values, null)
		}

		List<InterceptedUrl> annotatedActionNames = findActionRoles(clazz)
		if (annotatedActionNames) {
			actionRoleMap[controllerName] = annotatedActionNames
		}

		List<InterceptedUrl> closureAnnotatedActionNames = findActionClosures(clazz)
		if (closureAnnotatedActionNames) {
			actionClosureMap[controllerName] = closureAnnotatedActionNames
		}
	}

	protected String resolveFullControllerName(GrailsControllerClass controllerClass) {
		String controllerName = controllerClass.name
		String namespace = controllerClass.namespace
		if (namespace) {
			namespace = grailsUrlConverter.toUrlElement(namespace)
		}
		resolveFullControllerName grailsUrlConverter.toUrlElement(controllerName), namespace
	}

	protected String resolveFullControllerName(String controllerNameInUrlFormat, String namespaceInUrlFormat) {
		StringBuilder fullControllerName = new StringBuilder()
		if (namespaceInUrlFormat != null) {
			fullControllerName << namespaceInUrlFormat << ':'
		}
		fullControllerName << controllerNameInUrlFormat

		log.trace 'Resolved full controller name for controller "{}" and namespace "{}" as "{}"',
				  [controllerNameInUrlFormat, namespaceInUrlFormat, fullControllerName] as Object[]

		fullControllerName
	}

	protected List<InterceptedUrl> findActionRoles(Class<?> clazz) {

		GrailsControllerClass cc = (GrailsControllerClass)application.getArtefact(ControllerArtefactHandler.TYPE, clazz.name)
		String defaultAction = cc.defaultAction

		List<InterceptedUrl> actionRoles = []
		for (Method method in clazz.declaredMethods) {
			Annotation annotation = findSecuredAnnotation(method)
			if (annotation) {
				Collection<String> values = getValue(annotation)
				if (values) {
					log.trace 'found annotated method {} in {} with value(s) {}', method.name, clazz.name, values
					HttpMethod httpMethod = getHttpMethod(annotation)
					actionRoles << new InterceptedUrl(grailsUrlConverter.toUrlElement(method.name), values, httpMethod)

					if (method.name == defaultAction) {
						actionRoles << new InterceptedUrl('', values, httpMethod)
					}
				}
			}
		}
		actionRoles
	}

	protected List<InterceptedUrl> findActionClosures(Class<?> clazz) {
		List<InterceptedUrl> actionClosures = []
		for (Method method : clazz.declaredMethods) {
			grails.plugin.springsecurity.annotation.Secured annotation = method.getAnnotation(
					  grails.plugin.springsecurity.annotation.Secured)
			if (annotation && annotation.closure() != grails.plugin.springsecurity.annotation.Secured) {
				log.trace 'found annotation with a closure on method {} in {}', method.name, clazz.name
				actionClosures << new InterceptedUrl(grailsUrlConverter.toUrlElement(
						  method.name), annotation.closure(), getHttpMethod(annotation))
			}
		}
		actionClosures
	}

	protected Class<?> findClosureClass(grails.plugin.springsecurity.annotation.Secured annotation) {
		Class<?> closureClass = annotation.closure()
		closureClass == grails.plugin.springsecurity.annotation.Secured ? null : closureClass
	}

	protected Annotation findSecuredAnnotation(AccessibleObject annotatedTarget) {
		Annotation annotation = annotatedTarget.getAnnotation(grails.plugin.springsecurity.annotation.Secured)
		if (annotation) {
			return annotation
		}
		annotatedTarget.getAnnotation org.springframework.security.access.annotation.Secured
	}

	protected Collection<String> getValue(Annotation annotation) {
		String[] strings
		if (annotation instanceof grails.plugin.springsecurity.annotation.Secured) {
			strings = ((grails.plugin.springsecurity.annotation.Secured)annotation).value()
		}
		else {
			strings = ((org.springframework.security.access.annotation.Secured)annotation).value()
		}
		new LinkedHashSet<String>(Arrays.asList(strings))
	}

	protected HttpMethod getHttpMethod(Annotation annotation) {
		String method
		if (annotation instanceof grails.plugin.springsecurity.annotation.Secured) {
			method = ((grails.plugin.springsecurity.annotation.Secured)annotation).httpMethod()
			if (grails.plugin.springsecurity.annotation.Secured.ANY_METHOD == method) {
				method = null
			}
		}
		method == null ? null : HttpMethod.valueOf(method)
	}
}
