/* Copyright 2006-2012 the original author or authors.
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
package org.codehaus.groovy.grails.plugins.springsecurity;

import java.lang.annotation.Annotation;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.WordUtils;
import org.codehaus.groovy.grails.commons.ControllerArtefactHandler;
import org.codehaus.groovy.grails.commons.GrailsApplication;
import org.codehaus.groovy.grails.commons.GrailsClass;
import org.codehaus.groovy.grails.commons.GrailsControllerClass;
import org.codehaus.groovy.grails.web.context.ServletContextHolder;
import org.codehaus.groovy.grails.web.mapping.UrlMappingInfo;
import org.codehaus.groovy.grails.web.mapping.UrlMappingsHolder;
import org.codehaus.groovy.grails.web.servlet.mvc.GrailsParameterMap;
import org.codehaus.groovy.grails.web.servlet.mvc.GrailsWebRequest;
import org.codehaus.groovy.grails.web.util.WebUtils;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * A {@link FilterInvocationSecurityMetadataSource} that uses rules defined with Controller annotations
 * combined with static rules defined in <code>SecurityConfig.groovy</code>, e.g. for js, images, css
 * or for rules that cannot be expressed in a controller like '/**'.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
public class AnnotationFilterInvocationDefinition extends AbstractFilterInvocationDefinition {

	private static final List<String> ANNOTATION_CLASS_NAMES = Arrays.asList(
			grails.plugins.springsecurity.Secured.class.getName(),
			org.springframework.security.access.annotation.Secured.class.getName());

	private UrlMappingsHolder _urlMappingsHolder;
	private GrailsApplication _application;

	@Override
	protected String determineUrl(final FilterInvocation filterInvocation) {
		HttpServletRequest request = filterInvocation.getHttpRequest();
		HttpServletResponse response = filterInvocation.getHttpResponse();

		GrailsWebRequest existingRequest = WebUtils.retrieveGrailsWebRequest();

		String requestUrl = request.getRequestURI().substring(request.getContextPath().length());

		String url = null;
		try {
			GrailsWebRequest grailsRequest = new GrailsWebRequest(request, response,
					ServletContextHolder.getServletContext());
			WebUtils.storeGrailsWebRequest(grailsRequest);

			Map<String, Object> savedParams = copyParams(grailsRequest);

			for (UrlMappingInfo mapping : _urlMappingsHolder.matchAll(requestUrl)) {
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

		String actionName = mapping.getActionName();
		if (!StringUtils.hasLength(actionName)) {
			actionName = "";
		}

		String controllerName = mapping.getControllerName();

		if (isController(controllerName, actionName)) {
			if (!StringUtils.hasLength(actionName) || "null".equals(actionName)) {
				actionName = "index";
			}
			return ("/" + controllerName + "/" + actionName).trim();
		}

		return null;
	}

	private boolean isController(final String controllerName, final String actionName) {
		return _application.getArtefactForFeature(ControllerArtefactHandler.TYPE,
				"/" + controllerName + "/" + actionName) != null;
	}

	private void configureMapping(final UrlMappingInfo mapping, final GrailsWebRequest grailsRequest,
			final Map<String, Object> savedParams) {

		// reset params since mapping.configure() sets values
		GrailsParameterMap params = grailsRequest.getParams();
		params.clear();
		params.putAll(savedParams);

		mapping.configure(grailsRequest);
	}

	@SuppressWarnings("unchecked")
	private Map<String, Object> copyParams(final GrailsWebRequest grailsRequest) {
		return new HashMap<String, Object>(grailsRequest.getParams());
	}

	/**
	 * Called by the plugin to set controller role info.<br/>
	 *
	 * Reinitialize by calling <code>ctx.objectDefinitionSource.initialize(
	 * 	ctx.authenticateService.securityConfig.security.annotationStaticRules,
	 * 	ctx.grailsUrlMappingsHolder,
	 * 	grailsApplication.controllerClasses)</code>
	 *
	 * @param staticRules keys are URL patterns, values are role or token names for that pattern
	 * @param urlMappingsHolder mapping holder
	 * @param controllerClasses all controllers
	 */
	public void initialize(final Map<String, Collection<String>> staticRules,
			final UrlMappingsHolder urlMappingsHolder, final GrailsClass[] controllerClasses) {

		Map<String, Map<String, Set<String>>> actionRoleMap = new HashMap<String, Map<String,Set<String>>>();
		Map<String, Set<String>> classRoleMap = new HashMap<String, Set<String>>();

		Assert.notNull(staticRules, "staticRules map is required");
		Assert.notNull(urlMappingsHolder, "urlMappingsHolder is required");

		resetConfigs();

		_urlMappingsHolder = urlMappingsHolder;

		for (GrailsClass controllerClass : controllerClasses) {
			findControllerAnnotations((GrailsControllerClass)controllerClass, actionRoleMap, classRoleMap);
		}

		compileActionMap(actionRoleMap);
		compileClassMap(classRoleMap);
		compileStaticRules(staticRules);

		if (_log.isTraceEnabled()) {
			_log.trace("configs: " + getConfigAttributeMap());
		}
	}

	private void compileActionMap(final Map<String, Map<String, Set<String>>> map) {
		for (Map.Entry<String, Map<String, Set<String>>> controllerEntry : map.entrySet()) {
			String controllerName = controllerEntry.getKey();
			Map<String, Set<String>> actionRoles = controllerEntry.getValue();
			for (Map.Entry<String, Set<String>> actionEntry : actionRoles.entrySet()) {
				String actionName = actionEntry.getKey();
				Set<String> tokens = actionEntry.getValue();
				storeMapping(controllerName, actionName, tokens, false);
				if (actionName.endsWith("Flow")) {
					// WebFlow actions end in Flow but are accessed without the suffix, so guard both
					storeMapping(controllerName, actionName.substring(0, actionName.length() - 4), tokens, false);
				}
			}
		}
	}

	private void compileClassMap(final Map<String, Set<String>> classRoleMap) {
		for (Map.Entry<String, Set<String>> entry : classRoleMap.entrySet()) {
			String controllerName = entry.getKey();
			Set<String> tokens = entry.getValue();
			storeMapping(controllerName, null, tokens, false);
		}
	}

	private void compileStaticRules(final Map<String, Collection<String>> staticRules) {
		for (Map.Entry<String, Collection<String>> entry : staticRules.entrySet()) {
			String pattern = entry.getKey();
			Collection<String> tokens = entry.getValue();
			storeMapping(pattern, null, tokens, true);
		}
	}

	private void storeMapping(final String controllerNameOrPattern, final String actionName,
			final Collection<String> tokens, final boolean isPattern) {

		String fullPattern;
		if (isPattern) {
			fullPattern = controllerNameOrPattern;
		}
		else {
			StringBuilder sb = new StringBuilder();
			sb.append('/').append(controllerNameOrPattern);
			if (actionName != null) {
				sb.append('/').append(actionName);
			}
			sb.append("/**");
			fullPattern = sb.toString();
		}

		Collection<ConfigAttribute> configAttributes = buildConfigAttributes(tokens);

		Object key = getUrlMatcher().compile(fullPattern);
		Collection<ConfigAttribute> replaced = storeMapping(key, configAttributes);
		if (replaced != null) {
			_log.warn("replaced rule for '" + key + "' with tokens " + replaced
					+ " with tokens " + configAttributes);
		}
	}

	private void findControllerAnnotations(final GrailsControllerClass controllerClass,
			final Map<String, Map<String, Set<String>>> actionRoleMap,
			final Map<String, Set<String>> classRoleMap) {

		Class<?> clazz = controllerClass.getClazz();
		String controllerName = WordUtils.uncapitalize(controllerClass.getName());

		Annotation annotation = findAnnotation(clazz.getAnnotations());
		if (annotation != null) {
			classRoleMap.put(controllerName, asSet(getValue(annotation)));
		}

		Map<String, Set<String>> annotatedClosureNames = findActionRoles(clazz);
		if (annotatedClosureNames != null) {
			actionRoleMap.put(controllerName, annotatedClosureNames);
		}
	}

	private Map<String, Set<String>> findActionRoles(final Class<?> clazz) {
		// since action closures are defined as "def foo = ..." they're
		// fields, but they end up as private
		Map<String, Set<String>> actionRoles = new HashMap<String, Set<String>>();
		for (Field field : clazz.getDeclaredFields()) {
			Annotation annotation = findAnnotation(field.getAnnotations());
			if (annotation != null) {
				actionRoles.put(field.getName(), asSet(getValue(annotation)));
			}
		}
		for (Method method : clazz.getDeclaredMethods()) {
			Annotation annotation = findAnnotation(method.getAnnotations());
			if (annotation != null) {
				actionRoles.put(method.getName(), asSet(getValue(annotation)));
			}
		}
		return actionRoles;
	}

	private Annotation findAnnotation(Annotation[] annotations) {
		for (Annotation annotation : annotations) {
			if (ANNOTATION_CLASS_NAMES.contains(annotation.annotationType().getName())) {
				return annotation;
			}
		}
		return null;
	}

	private String[] getValue(Annotation annotation) {
		if (annotation instanceof grails.plugins.springsecurity.Secured) {
			return ((grails.plugins.springsecurity.Secured)annotation).value();
		}
		return ((org.springframework.security.access.annotation.Secured)annotation).value();
	}

	private Set<String> asSet(final String[] strings) {
		Set<String> set = new HashSet<String>();
		for (String string : strings) {
			set.add(string);
		}
		return set;
	}

	/**
	 * Dependency injection for the application.
	 * @param application the application
	 */
	public void setApplication(GrailsApplication application) {
		_application = application;
	}
}
