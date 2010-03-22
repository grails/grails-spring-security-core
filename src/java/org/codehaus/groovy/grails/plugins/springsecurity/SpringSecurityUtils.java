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
package org.codehaus.groovy.grails.plugins.springsecurity;

import grails.util.Environment;
import groovy.lang.GroovyClassLoader;
import groovy.util.ConfigObject;
import groovy.util.ConfigSlurper;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.GrantedAuthorityImpl;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.util.StringUtils;

/**
 * Helper methods.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
public final class SpringSecurityUtils {

	private static ConfigObject securityConfig;

	public static final Map<Integer, String> ORDERED_FILTERS = new HashMap<Integer, String>();

	private SpringSecurityUtils() {
		// static only
	}

	/**
	 * Extract the role names from authorities.
	 * @param authorities  the authorities (a collection or array of {@link GrantedAuthority}).
	 * @return  the names
	 */
	public static Set<String> authoritiesToRoles(final Object authorities) {
		Set<String> roles = new HashSet<String>();
		for (Object authority : ReflectionUtils.asList(authorities)) {
			String authorityName = ((GrantedAuthority)authority).getAuthority();
			if (null == authorityName) {
				throw new IllegalArgumentException(
						"Cannot process GrantedAuthority objects which return null from getAuthority() - attempting to process "
						+ authority);
			}
			roles.add(authorityName);
		}

		return roles;
	}

	/**
	 * Get the current user's authorities.
	 * @return  a list of authorities (empty if not authenticated).
	 */
	public static Collection<GrantedAuthority> getPrincipalAuthorities() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (null == authentication) {
			return Collections.emptyList();
		}

		Collection<GrantedAuthority> authorities = authentication.getAuthorities();
		if (authorities == null) {
			return Collections.emptyList();
		}

		return authorities;
	}

	/**
	 * Split the role names and create {@link GrantedAuthority}s for each.
	 * @param authorizationsString  comma-delimited role names
	 * @return authorities (possibly empty)
	 */
	public static List<GrantedAuthority> parseAuthoritiesString(final String authorizationsString) {
		List<GrantedAuthority> requiredAuthorities = new ArrayList<GrantedAuthority>();
		for (String auth : StringUtils.commaDelimitedListToStringArray(authorizationsString)) {
			auth = auth.trim();
			if (auth.length() > 0) {
				requiredAuthorities.add(new GrantedAuthorityImpl(auth));
			}
		}

		return requiredAuthorities;
	}

	/**
	 * Find authorities in <code>granted</code> that are also in <code>required</code>.
	 * @param granted  the granted authorities (a collection or array of {@link SpringSecurityUtils}).
	 * @param required  the required authorities (a collection or array of {@link SpringSecurityUtils}).
	 * @return the authority names
	 */
	public static Set<String> retainAll(final Object granted, final Object required) {
		Set<String> grantedRoles = authoritiesToRoles(granted);
		Set<String> requiredRoles = authoritiesToRoles(required);
		grantedRoles.retainAll(requiredRoles);
		return grantedRoles;
	}

	/**
	 * Check if the current user has all of the specified roles.
	 * @param roles  a comma-delimited list of role names
	 * @return <code>true</code> if the user is authenticated and has all the roles
	 */
	public static boolean ifAllGranted(final String roles) {
		Collection<GrantedAuthority> granted = getPrincipalAuthorities();
		return granted.containsAll(parseAuthoritiesString(roles));
	}

	/**
	 * Check if the current user has none of the specified roles.
	 * @param roles  a comma-delimited list of role names
	 * @return <code>true</code> if the user is authenticated and has none the roles
	 */
	public static boolean ifNotGranted(final String roles) {
		Collection<GrantedAuthority> granted = getPrincipalAuthorities();
		Set<String> grantedCopy = retainAll(granted, parseAuthoritiesString(roles));
		return grantedCopy.isEmpty();
	}

	/**
	 * Check if the current user has any of the specified roles.
	 * @param roles  a comma-delimited list of role names
	 * @return <code>true</code> if the user is authenticated and has any the roles
	 */
	public static boolean ifAnyGranted(final String roles) {
		Collection<GrantedAuthority> granted = getPrincipalAuthorities();
		Set<String> grantedCopy = retainAll(granted, parseAuthoritiesString(roles));
		return !grantedCopy.isEmpty();
	}

	/**
	 * Parse and load the security configuration.
	 * @return  the configuration
	 */
	public static synchronized ConfigObject getSecurityConfig() {
		if (securityConfig == null) {
			reloadSecurityConfig();
		}

		return securityConfig;
	}

	/**
	 * Allow a secondary plugin to add config attributes.
	 * @param className  the name of the config class.
	 */
	public static synchronized void loadSecondaryConfig(final String className) {
		mergeConfig(getSecurityConfig(), className);
	}

	/**
	 * Force a reload of the security configuration.
	 */
	public static void reloadSecurityConfig() {
		mergeConfig(ReflectionUtils.getSecurityConfig(), "DefaultSecurityConfig");
	}

	/**
	 * Check if the request was triggered by an Ajax call.
	 * @param request the request
	 * @return <code>true</code> if Ajax
	 */
	public static boolean isAjax(final HttpServletRequest request) {

		String ajaxHeaderName = (String)ReflectionUtils.getConfigProperty("ajaxHeader");

		// look for an ajax=true parameter
		if ("true".equals(request.getParameter("ajax"))) {
			return true;
		}

		// check the current request's headers
		if (request.getHeader(ajaxHeaderName) != null) {
			return true;
		}

		// check the SavedRequest's headers
		SavedRequest savedRequest = (SavedRequest)request.getSession().getAttribute(
				DefaultSavedRequest.SPRING_SECURITY_SAVED_REQUEST_KEY);
		if (savedRequest != null) {
			return !savedRequest.getHeaderValues(ajaxHeaderName).isEmpty();
		}

		return false;
	}

	/**
	 * Register a provider bean name.
	 * @param beanName  the Spring bean name of the provider
	 */
	@SuppressWarnings("unchecked")
	public static void registerProvider(final String beanName) {
		getOrCreateConfigList("providerNames").add(beanName);
	}

	/**
	 * Register a filter bean name in a specified position in the chain.
	 * @param beanName  the Spring bean name of the filter
	 * @param order  the position
	 */
	public static void registerFilter(final String beanName, final SecurityFilterPosition order) {
		registerFilter(beanName, order.getOrder());
	}

	/**
	 * Register a filter bean name in a specified position in the chain.
	 * @param beanName  the Spring bean name of the filter
	 * @param order  the position (see {@link SecurityFilterPosition})
	 */
	public static void registerFilter(final String beanName, final int order) {
		ORDERED_FILTERS.put(order, beanName);
	}

	@SuppressWarnings("unchecked")
	private static List getOrCreateConfigList(final String name) {
		Object o = ReflectionUtils.getConfigProperty(name);
		List<String> list;
		if (o instanceof List<?>) {
			list = (List)o;
		}
		else {
			list = new ArrayList();
		}
		ReflectionUtils.setConfigProperty(name, list);
		return list;
	}

	/**
	 * Merge in a secondary config (provided by a plugin as defaults) into the main config.
	 * @param currentConfig  the current configuration
	 * @param className  the name of the config class to load
	 */
	private static void mergeConfig(final ConfigObject currentConfig, final String className) {
		GroovyClassLoader classLoader = new GroovyClassLoader(SpringSecurityUtils.class.getClassLoader());
		ConfigSlurper slurper = new ConfigSlurper(Environment.getCurrent().getName());
		ConfigObject secondaryConfig;
		try {
			secondaryConfig = slurper.parse(classLoader.loadClass(className));
		}
		catch (ClassNotFoundException e) {
			// TODO fix this
			throw new RuntimeException(e);
		}

		securityConfig = mergeConfig(currentConfig, (ConfigObject)secondaryConfig.getProperty("security"));
		ReflectionUtils.setSecurityConfig(securityConfig);
	}

	/**
	 * Merge two configs together. The order is important; if <code>secondary</code> is not null then
	 * start with that and merge the main config on top of that. This lets the <code>secondary</code>
	 * config act as default values but let user-supplied values in the main config override them.
	 *
	 * @param currentConfig  the main config, starting from Config.groovy
	 * @param secondary  new default values
	 * @return the merged configs
	 */
	@SuppressWarnings("unchecked")
	private static ConfigObject mergeConfig(final ConfigObject currentConfig, final ConfigObject secondary) {
		ConfigObject config = new ConfigObject();
		if (secondary == null) {
			config.putAll(currentConfig);
		}
		else {
			config.putAll(secondary.merge(currentConfig));
		}
		return config;
	}
}
