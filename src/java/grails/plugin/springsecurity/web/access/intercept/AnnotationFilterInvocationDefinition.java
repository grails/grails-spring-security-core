/* Copyright 2006-2015 SpringSource.
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
package grails.plugin.springsecurity.web.access.intercept;

import grails.plugin.springsecurity.InterceptedUrl;
import grails.plugin.springsecurity.access.vote.ClosureConfigAttribute;
import grails.web.UrlConverter;
import groovy.lang.Closure;

import java.lang.annotation.Annotation;
import java.lang.reflect.AccessibleObject;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.codehaus.groovy.grails.commons.ControllerArtefactHandler;
import org.codehaus.groovy.grails.commons.GrailsApplication;
import org.codehaus.groovy.grails.commons.GrailsClass;
import org.codehaus.groovy.grails.commons.GrailsControllerClass;
import org.codehaus.groovy.grails.plugins.web.api.ResponseMimeTypesApi;
import org.codehaus.groovy.grails.web.mapping.UrlMappingInfo;
import org.codehaus.groovy.grails.web.mapping.UrlMappingsHolder;
import org.codehaus.groovy.grails.web.servlet.mvc.GrailsParameterMap;
import org.codehaus.groovy.grails.web.servlet.mvc.GrailsWebRequest;
import org.codehaus.groovy.grails.web.util.WebUtils;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.util.Assert;
import org.springframework.util.ReflectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.context.ServletContextAware;

/**
 * A {@link FilterInvocationSecurityMetadataSource} that uses rules defined with
 * Controller annotations combined with static rules defined in
 * <code>SecurityConfig.groovy</code>, e.g. for js, images, css or for rules
 * that cannot be expressed in a controller like '/**'.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
public class AnnotationFilterInvocationDefinition extends AbstractFilterInvocationDefinition implements ServletContextAware {

   protected static final String SLASH = "/";

	protected GrailsApplication application;
	protected ResponseMimeTypesApi responseMimeTypesApi;
	protected ServletContext servletContext;
	protected UrlConverter grailsUrlConverter;
	protected UrlMappingsHolder urlMappingsHolder;

	@Override
	protected String determineUrl(final FilterInvocation filterInvocation) {
		HttpServletRequest request = filterInvocation.getHttpRequest();
		HttpServletResponse response = filterInvocation.getHttpResponse();

		GrailsWebRequest existingRequest;
		try {
			existingRequest = WebUtils.retrieveGrailsWebRequest();
		}
		catch (IllegalStateException e) {
			throw new IllegalStateException(
				"There was a problem retrieving the current GrailsWebRequest. This usually indicates a filter ordering " +
				"issue in web.xml (the 'springSecurityFilterChain' filter-mapping element must be positioned after the " +
				"'grailsWebRequest' element when using @Secured annotations) but this should be handled correctly by the " +
				"webxml plugin. Ensure that the webxml plugin is installed (it should be transitively installed as a " +
				"dependency of the spring-security-core plugin)");
		}

		String requestUrl = calculateUri(request);

		String url = null;
		try {
			GrailsWebRequest grailsRequest = new GrailsWebRequest(request, response, servletContext);
			WebUtils.storeGrailsWebRequest(grailsRequest);

			Map<String, Object> savedParams = copyParams(grailsRequest);

			UrlMappingInfo[] urlInfos;
			if (grails23Plus) {
				urlInfos = grails.plugin.springsecurity.ReflectionUtils.matchAllUrlMappings(urlMappingsHolder, requestUrl, grailsRequest, responseMimeTypesApi);
			}
			else {
				urlInfos = urlMappingsHolder.matchAll(requestUrl);
			}

			for (UrlMappingInfo mapping : urlInfos) {
				if (grails23Plus && grails.plugin.springsecurity.ReflectionUtils.isRedirect(mapping)) {
					break;
				}

				configureMapping(mapping, grailsRequest, savedParams);

				url = findGrailsUrl(mapping);
				if (url != null) {
					break;
				}
			}
		}
		finally {
			if (existingRequest == null) {
				WebUtils.clearGrailsWebRequest();
			}
			else {
				WebUtils.storeGrailsWebRequest(existingRequest);
			}
		}

		if (!StringUtils.hasLength(url)) {
			// probably css/js/image
			url = requestUrl;
		}

		return lowercaseAndStripQuerystring(url);
	}

	protected String findGrailsUrl(final UrlMappingInfo mapping) {

		String uri = mapping.getURI();
		if (StringUtils.hasLength(uri)) {
			return uri;
		}

		String viewName = mapping.getViewName();
		if (viewName != null) {
			if (!viewName.startsWith(SLASH)) {
				viewName = SLASH + viewName;
			}
			return viewName;
		}

		String actionName = mapping.getActionName();
		if (!StringUtils.hasLength(actionName)) {
			actionName = "";
		}

		String controllerName = mapping.getControllerName();

		if (isController(controllerName, actionName)) {
			return createControllerUri(controllerName, actionName);
		}

		if (grails23Plus && controllerName != null) {
			String namespace = mapping.getNamespace();
			if (namespace != null) {
				String fullControllerName = resolveFullControllerName(controllerName, namespace);
				return createControllerUri(fullControllerName, actionName);
			}
		}

		return null;
	}

	protected String createControllerUri(String controllerName, String actionName) {
		if (!StringUtils.hasLength(actionName) || "null".equals(actionName)) {
			actionName = "index";
		}
		return (SLASH + controllerName + SLASH + actionName).trim();
	}

	protected boolean isController(final String controllerName, final String actionName) {
		return application.getArtefactForFeature(ControllerArtefactHandler.TYPE,
				SLASH + controllerName + SLASH + actionName) != null;
	}

	protected void configureMapping(final UrlMappingInfo mapping, final GrailsWebRequest grailsRequest,
			final Map<String, Object> savedParams) {

		// reset params since mapping.configure() sets values
		GrailsParameterMap params = grailsRequest.getParams();
		params.clear();
		params.putAll(savedParams);

		mapping.configure(grailsRequest);
	}

	@SuppressWarnings("unchecked")
	protected Map<String, Object> copyParams(final GrailsWebRequest grailsRequest) {
		return new LinkedHashMap<String, Object>(grailsRequest.getParams());
	}

	/**
	 * Called by the plugin to set controller role info.<br/>
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
	public void initialize(final Object staticRules,
			final UrlMappingsHolder mappingsHolder, final GrailsClass[] controllerClasses) {

		Assert.notNull(staticRules, "staticRules map is required");
		Assert.notNull(mappingsHolder, "urlMappingsHolder is required");

		resetConfigs();

		urlMappingsHolder = mappingsHolder;

		Map<String, List<InterceptedUrl>> actionRoleMap = new LinkedHashMap<String, List<InterceptedUrl>>();
		List<InterceptedUrl> classRoleMap = new ArrayList<InterceptedUrl>();
		Map<String, List<InterceptedUrl>> actionClosureMap = new LinkedHashMap<String, List<InterceptedUrl>>();
		List<InterceptedUrl> classClosureMap = new ArrayList<InterceptedUrl>();

		for (GrailsClass controllerClass : controllerClasses) {
			findControllerAnnotations((GrailsControllerClass)controllerClass, actionRoleMap, classRoleMap, actionClosureMap, classClosureMap);
		}

		compileStaticRules(staticRules);
		compileActionClosureMap(actionClosureMap);
		compileClassClosureMap(classClosureMap);
		compileActionMap(actionRoleMap);
		compileClassMap(classRoleMap);

		if (log.isTraceEnabled()) {
			log.trace("configs: " + getConfigAttributeMap());
		}
	}

	protected void compileActionMap(final Map<String, List<InterceptedUrl>> map) {
		for (Map.Entry<String, List<InterceptedUrl>> controllerEntry : map.entrySet()) {
			String controllerName = controllerEntry.getKey();
			for (InterceptedUrl iu : controllerEntry.getValue()) {
				Collection<ConfigAttribute> configAttributes = iu.getConfigAttributes();
				String actionName = iu.getPattern();
				HttpMethod method = iu.getHttpMethod();
				storeMapping(controllerName, actionName, configAttributes, false, method);
				if (actionName.endsWith("Flow")) {
					// WebFlow actions end in Flow but are accessed without the suffix, so guard both
					storeMapping(controllerName, actionName.substring(0, actionName.length() - 4), configAttributes, false, method);
				}
			}
		}
	}

	protected void compileActionClosureMap(final Map<String, List<InterceptedUrl>> map) {
		for (Map.Entry<String, List<InterceptedUrl>> controllerEntry : map.entrySet()) {
			String controllerName = controllerEntry.getKey();
			List<InterceptedUrl> actionClosures = controllerEntry.getValue();
			for (InterceptedUrl iu : actionClosures) {
				String actionName = iu.getPattern();
				Class<?> closureClass = iu.getClosureClass();
				HttpMethod method = iu.getHttpMethod();
				storeMapping(controllerName, actionName, closureClass, method);
				if (actionName.endsWith("Flow")) {
					// WebFlow actions end in Flow but are accessed without the suffix, so guard both
					storeMapping(controllerName, actionName.substring(0, actionName.length() - 4), closureClass, method);
				}
			}
		}
	}

	protected void compileClassMap(final List<InterceptedUrl> classRoleMap) {
		for (InterceptedUrl iu : classRoleMap) {
			storeMapping(iu.getPattern(), null, iu.getConfigAttributes(), false, iu.getHttpMethod());
		}
	}

	protected void compileClassClosureMap(final List<InterceptedUrl> classClosureMap) {
		for (InterceptedUrl iu : classClosureMap) {
			storeMapping(iu.getPattern(), null, iu.getClosureClass(), iu.getHttpMethod());
		}
	}

	protected Closure<?> newInstance(final Class<?> closureClass) {
		try {
			Constructor<?> constructor = closureClass.getConstructor(Object.class, Object.class);
			ReflectionUtils.makeAccessible(constructor);
			return (Closure<?>) constructor.newInstance(this, this);
		}
		catch (NoSuchMethodException e) {
			ReflectionUtils.handleReflectionException(e);
		}
		catch (InstantiationException e) {
			ReflectionUtils.handleReflectionException(e);
		}
		catch (IllegalAccessException e) {
			ReflectionUtils.handleReflectionException(e);
		}
		catch (InvocationTargetException e) {
			ReflectionUtils.handleInvocationTargetException(e);
		}
		return null;
	}

	@SuppressWarnings("unchecked")
	protected void compileStaticRules(final Object staticRules) {
		List<InterceptedUrl> rules;
		if (staticRules instanceof Map) {
			rules = grails.plugin.springsecurity.ReflectionUtils.splitMap((Map<String, Object>)staticRules);
		}
		else if (staticRules instanceof List) {
			rules = grails.plugin.springsecurity.ReflectionUtils.splitMap((List<Map<String, Object>>)staticRules);
		}
		else {
			return;
		}

		for (InterceptedUrl iu : rules) {
			storeMapping(iu.getPattern(), null, iu.getConfigAttributes(), true, iu.getHttpMethod());
		}
	}

	protected void storeMapping(final String controllerNameOrPattern, final String actionName,
			final Collection<ConfigAttribute> configAttributes, final boolean isPattern, final HttpMethod method) {

		for (String pattern : generatePatterns(controllerNameOrPattern, actionName, isPattern)) {
			doStoreMapping(pattern, method, configAttributes);
		}
	}

	protected void storeMapping(final String controllerName, final String actionName, final Class<?> closureClass, final HttpMethod method) {
		if (closureClass == grails.plugin.springsecurity.annotation.Secured.class) {
			return;
		}

		for (String pattern : generatePatterns(controllerName, actionName, false)) {
			Collection<ConfigAttribute> configAttributes = new ArrayList<ConfigAttribute>();
			configAttributes.add(new ClosureConfigAttribute(newInstance(closureClass)));

			String key = pattern.toLowerCase();
			InterceptedUrl replaced = storeMapping(key, method, configAttributes);
			if (replaced != null) {
				log.warn("replaced rule for '{}' with tokens {} with tokens {}", new Object[] { key, replaced.getConfigAttributes(), configAttributes });
			}
		}
	}

	protected List<String> generatePatterns(final String controllerNameOrPattern, final String actionName, final boolean isPattern) {

		List<String> patterns = new ArrayList<String>();

		if (isPattern) {
			patterns.add(controllerNameOrPattern);
		}
		else {
			StringBuilder sb = new StringBuilder();
			sb.append('/').append(controllerNameOrPattern);
			if (actionName != null) {
				sb.append('/').append(actionName);
			}
			patterns.add(sb.toString());
			patterns.add(sb.toString() + ".*");

			sb.append("/**");
			patterns.add(sb.toString());
		}

		return patterns;
	}

	protected void doStoreMapping(final String fullPattern, final HttpMethod method, final Collection<ConfigAttribute> configAttributes) {
		String key = fullPattern.toString().toLowerCase();
		InterceptedUrl replaced = storeMapping(key, method, configAttributes);
		if (replaced != null) {
			log.warn("replaced rule for '" + key + "' with tokens " + replaced.getConfigAttributes() +
					" with tokens " + configAttributes);
		}
	}

	protected void findControllerAnnotations(
			final GrailsControllerClass controllerClass,
			final Map<String, List<InterceptedUrl>> actionRoleMap,
			final List<InterceptedUrl> classRoleMap,
			final Map<String, List<InterceptedUrl>> actionClosureMap,
			final List<InterceptedUrl> classClosureMap) {

		Class<?> clazz = controllerClass.getClazz();
		String controllerName = resolveFullControllerName(controllerClass);

		Annotation annotation = clazz.getAnnotation(org.springframework.security.access.annotation.Secured.class);
		if (annotation == null) {
			annotation = clazz.getAnnotation(grails.plugin.springsecurity.annotation.Secured.class);
			if (annotation != null) {
				Class<?> closureClass = findClosureClass((grails.plugin.springsecurity.annotation.Secured)annotation);
				if (closureClass == null) {
					classRoleMap.add(new InterceptedUrl(controllerName, getValue(annotation), getHttpMethod(annotation)));
				}
				else {
					classClosureMap.add(new InterceptedUrl(controllerName, closureClass, getHttpMethod(annotation)));
				}
			}
		}
		else {
			classRoleMap.add(new InterceptedUrl(controllerName, getValue(annotation), null));
		}

		List<InterceptedUrl> annotatedActionNames = findActionRoles(clazz);
		if (annotatedActionNames != null && !annotatedActionNames.isEmpty()) {
			actionRoleMap.put(controllerName, annotatedActionNames);
		}

		List<InterceptedUrl> closureAnnotatedActionNames = findActionClosures(clazz);
		if (closureAnnotatedActionNames != null && !closureAnnotatedActionNames.isEmpty()) {
			actionClosureMap.put(controllerName, closureAnnotatedActionNames);
		}
	}

	protected String resolveFullControllerName(final GrailsControllerClass controllerClass) {
		String controllerName = controllerClass.getName();
		String namespace = null;
		if (grails23Plus) {
			namespace = controllerClass.getNamespace();
			if (namespace != null) {
				namespace = grailsUrlConverter.toUrlElement(namespace);
			}
		}
		return resolveFullControllerName(grailsUrlConverter.toUrlElement(controllerName), namespace);
	}

	protected String resolveFullControllerName(String controllerNameInUrlFormat, String namespaceInUrlFormat) {
		StringBuilder fullControllerName = new StringBuilder();
		if (namespaceInUrlFormat != null) {
			fullControllerName.append(namespaceInUrlFormat).append(":");
		}
		fullControllerName.append(controllerNameInUrlFormat);
		return fullControllerName.toString();
	}

	protected List<InterceptedUrl> findActionRoles(final Class<?> clazz) {
		List<InterceptedUrl> actionRoles = new ArrayList<InterceptedUrl>();
		for (Method method : clazz.getDeclaredMethods()) {
			Annotation annotation = findSecuredAnnotation(method);
			if (annotation != null) {
				Collection<String> values = getValue(annotation);
				if (!values.isEmpty()) {
					actionRoles.add(new InterceptedUrl(grailsUrlConverter.toUrlElement(method.getName()), values, getHttpMethod(annotation)));
				}
			}
		}
		return actionRoles;
	}

	protected List<InterceptedUrl> findActionClosures(final Class<?> clazz) {
		List<InterceptedUrl> actionClosures = new ArrayList<InterceptedUrl>();
		for (Method method : clazz.getDeclaredMethods()) {
			grails.plugin.springsecurity.annotation.Secured annotation = method.getAnnotation(
					grails.plugin.springsecurity.annotation.Secured.class);
			if (annotation != null && annotation.closure() != grails.plugin.springsecurity.annotation.Secured.class) {
				actionClosures.add(new InterceptedUrl(grailsUrlConverter.toUrlElement(
						method.getName()), annotation.closure(), getHttpMethod(annotation)));
			}
		}
		return actionClosures;
	}

	protected Class<?> findClosureClass(final grails.plugin.springsecurity.annotation.Secured annotation) {
		Class<?> closureClass = annotation.closure();
		return closureClass == grails.plugin.springsecurity.annotation.Secured.class ? null : closureClass;
	}

	protected Annotation findSecuredAnnotation(final AccessibleObject annotatedTarget) {
		Annotation annotation = annotatedTarget.getAnnotation(grails.plugin.springsecurity.annotation.Secured.class);
		if (annotation != null) {
			return annotation;
		}
		return annotatedTarget.getAnnotation(org.springframework.security.access.annotation.Secured.class);
	}

	protected Collection<String> getValue(final Annotation annotation) {
		String[] strings;
		if (annotation instanceof grails.plugin.springsecurity.annotation.Secured) {
			strings = ((grails.plugin.springsecurity.annotation.Secured)annotation).value();
		}
		else {
			strings = ((org.springframework.security.access.annotation.Secured)annotation).value();
		}
		return new LinkedHashSet<String>(Arrays.asList(strings));
	}

	protected HttpMethod getHttpMethod(final Annotation annotation) {
		String method = null;
		if (annotation instanceof grails.plugin.springsecurity.annotation.Secured) {
			method = ((grails.plugin.springsecurity.annotation.Secured)annotation).httpMethod();
			if (grails.plugin.springsecurity.annotation.Secured.ANY_METHOD.equals(method)) {
				method = null;
			}
		}
		return method == null ? null : HttpMethod.valueOf(method);
	}

	/**
	 * Dependency injection for the application.
	 * @param app the application
	 */
	public void setApplication(GrailsApplication app) {
		application = app;
	}

	/**
	 * Dependency injection for the grailsUrlConverter bean.
	 * @param urlConverter the converter
	 */
	public void setGrailsUrlConverter(UrlConverter urlConverter) {
		grailsUrlConverter = urlConverter;
	}

	/**
	 * Dependency injection for the responseMimeTypesApi bean.
	 * @param api the bean
	 */
	public void setResponseMimeTypesApi(ResponseMimeTypesApi api) {
		responseMimeTypesApi = api;
	}

	/* (non-Javadoc)
	 * @see org.springframework.web.context.ServletContextAware#setServletContext(javax.servlet.ServletContext)
	 */
	public void setServletContext(ServletContext sc) {
		servletContext = sc;
	}
}
