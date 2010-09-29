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
import groovy.lang.Closure;
import groovy.lang.GroovyClassLoader;
import groovy.util.ConfigObject;
import groovy.util.ConfigSlurper;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;

import javax.servlet.Filter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.codehaus.groovy.grails.commons.ApplicationHolder;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.GrantedAuthorityImpl;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserCache;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.switchuser.SwitchUserFilter;
import org.springframework.security.web.authentication.switchuser.SwitchUserGrantedAuthority;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.util.StringUtils;

/**
 * Helper methods.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
public final class SpringSecurityUtils {

	private static ConfigObject securityConfig;

	/**
	 * Default value for the name of the Ajax header.
	 */
	public static final String AJAX_HEADER = "X-Requested-With";

	/**
	 * Default ordered filter names. Here to let plugins add or remove them. Can be overridden by config.
	 */
	public static final Map<Integer, String> ORDERED_FILTERS = new HashMap<Integer, String>();

	/**
	 * Set by SpringSecurityCoreGrailsPlugin; contains the actual filter beans in order.
	 */
	public static final SortedMap<Integer, Filter> CONFIGURED_ORDERED_FILTERS =
		new TreeMap<Integer, Filter>();

	/**
	 * Default voter names. Here to let plugins add or remove them. Can be overridden by config.
	 */
	public static final List<String> VOTER_NAMES = new ArrayList<String>();

	/**
	 * Default authentication provider names. Here to let plugins add or remove them. Can be overridden by config.
	 */
	public static final List<String> PROVIDER_NAMES = new ArrayList<String>();

	/**
	 * Default logout handler names. Here to let plugins add or remove them. Can be overridden by config.
	 */
	public static final List<String> LOGOUT_HANDLER_NAMES = new ArrayList<String>();

	static {
		VOTER_NAMES.add("authenticatedVoter");
		VOTER_NAMES.add("roleVoter");
		VOTER_NAMES.add("webExpressionVoter");

		PROVIDER_NAMES.add("daoAuthenticationProvider");
		PROVIDER_NAMES.add("anonymousAuthenticationProvider");
		PROVIDER_NAMES.add("rememberMeAuthenticationProvider");

		LOGOUT_HANDLER_NAMES.add("rememberMeServices");
		LOGOUT_HANDLER_NAMES.add("securityContextLogoutHandler");
	}

	/**
	 * Used to ensure that all authenticated users have at least one granted authority to work
	 * around Spring Security code that assumes at least one. By granting this non-authority,
	 * the user can't do anything but gets past the somewhat arbitrary restrictions.
	 */
	public static final String NO_ROLE = "ROLE_NO_ROLES";

	private SpringSecurityUtils() {
		// static only
	}

	public static void reset()
	{
		ORDERED_FILTERS.clear();
		CONFIGURED_ORDERED_FILTERS.clear();
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
		if (authentication == null) {
			return Collections.emptyList();
		}

		Collection<GrantedAuthority> authorities = authentication.getAuthorities();
		if (authorities == null) {
			return Collections.emptyList();
		}

		// remove the fake role if it's there
		Collection<GrantedAuthority> copy = new ArrayList<GrantedAuthority>(authorities);
		for (Iterator<GrantedAuthority> iter = copy.iterator(); iter.hasNext();) {
			if (iter.next().getAuthority().equals(NO_ROLE)) {
				iter.remove();
			}
		}

		return copy;
	}

	/**
	 * Split the role names and create {@link GrantedAuthority}s for each.
	 * @param roleNames  comma-delimited role names
	 * @return authorities (possibly empty)
	 */
	public static List<GrantedAuthority> parseAuthoritiesString(final String roleNames) {
		List<GrantedAuthority> requiredAuthorities = new ArrayList<GrantedAuthority>();
		for (String auth : StringUtils.commaDelimitedListToStringArray(roleNames)) {
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
		Collection<GrantedAuthority> inferred = findInferredAuthorities(getPrincipalAuthorities());
		return inferred.containsAll(parseAuthoritiesString(roles));
	}

	/**
	 * Check if the current user has none of the specified roles.
	 * @param roles  a comma-delimited list of role names
	 * @return <code>true</code> if the user is authenticated and has none the roles
	 */
	public static boolean ifNotGranted(final String roles) {
		Collection<GrantedAuthority> inferred = findInferredAuthorities(getPrincipalAuthorities());
		Set<String> grantedCopy = retainAll(inferred, parseAuthoritiesString(roles));
		return grantedCopy.isEmpty();
	}

	/**
	 * Check if the current user has any of the specified roles.
	 * @param roles  a comma-delimited list of role names
	 * @return <code>true</code> if the user is authenticated and has any the roles
	 */
	public static boolean ifAnyGranted(final String roles) {
		Collection<GrantedAuthority> inferred = findInferredAuthorities(getPrincipalAuthorities());
		Set<String> grantedCopy = retainAll(inferred, parseAuthoritiesString(roles));
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
	 * Reset the config for testing or after a dev mode Config.groovy change.
	 */
	public static synchronized void resetSecurityConfig() {
		securityConfig = null;
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

		// check the current request's headers
		if (request.getHeader(ajaxHeaderName) != null) {
			return true;
		}

		// look for an ajax=true parameter
		if ("true".equals(request.getParameter("ajax"))) {
			return true;
		}

		// check the SavedRequest's headers
		SavedRequest savedRequest = (SavedRequest)request.getSession().getAttribute(WebAttributes.SAVED_REQUEST);
		if (savedRequest != null) {
			return !savedRequest.getHeaderValues(ajaxHeaderName).isEmpty();
		}

		return false;
	}

	/**
	 * Register a provider bean name.
	 * <p/>
	 * Note - only for use by plugins during bean building.
	 *
	 * @param beanName  the Spring bean name of the provider
	 */
	public static void registerProvider(final String beanName) {
		PROVIDER_NAMES.add(0, beanName);
	}

	/**
	 * Register a logout handler bean name.
	 * <p/>
	 * Note - only for use by plugins during bean building.
	 *
	 * @param beanName  the Spring bean name of the handler
	 */
	public static void registerLogoutHandler(final String beanName) {
		LOGOUT_HANDLER_NAMES.add(0, beanName);
	}

	/**
	 * Register a voter bean name.
	 * <p/>
	 * Note - only for use by plugins during bean building.
	 *
	 * @param beanName  the Spring bean name of the voter
	 */
	public static void registerVoter(final String beanName) {
		VOTER_NAMES.add(0, beanName);
	}

	/**
	 * Register a filter bean name in a specified position in the chain.
	 * <p/>
	 * Note - only for use by plugins during bean building - to register at runtime
	 * (preferably in BootStrap) use <code>clientRegisterFilter</code>.
	 *
	 * @param beanName  the Spring bean name of the filter
	 * @param order  the position
	 */
	public static void registerFilter(final String beanName, final SecurityFilterPosition order) {
		registerFilter(beanName, order.getOrder());
	}

	/**
	 * Register a filter bean name in a specified position in the chain.
	 * <p/>
	 * Note - only for use by plugins during bean building - to register at runtime
	 * (preferably in BootStrap) use <code>clientRegisterFilter</code>.
	 *
	 * @param beanName  the Spring bean name of the filter
	 * @param order  the position (see {@link SecurityFilterPosition})
	 */
	public static void registerFilter(final String beanName, final int order) {
		String oldName = ORDERED_FILTERS.get(order);
		if (oldName != null) {
			throw new IllegalArgumentException("Cannot register filter '" + beanName +
					"' at position " + order + "; '" + oldName +
					"' is already registered in that position");
		}
		ORDERED_FILTERS.put(order, beanName);
	}

	/**
	 * Register a filter in a specified position in the chain.
	 * <p/>
	 * Note - this is for use in application code after the plugin has initialized,
	 * e.g. in BootStrap where you want to register a custom filter in the correct
	 * order without dealing with the existing configured filters.
	 *
	 * @param beanName  the Spring bean name of the filter
	 * @param order  the position
	 */
	public static void clientRegisterFilter(final String beanName, final SecurityFilterPosition order) {
		clientRegisterFilter(beanName, order.getOrder());
	}

	/**
	 * Register a filter in a specified position in the chain.
	 * <p/>
	 * Note - this is for use in application code after the plugin has initialized,
	 * e.g. in BootStrap where you want to register a custom filter in the correct
	 * order without dealing with the existing configured filters.
	 *
	 * @param beanName  the Spring bean name of the filter
	 * @param order  the position (see {@link SecurityFilterPosition})
	 */
	public static void clientRegisterFilter(final String beanName, final int order) {

		Filter oldFilter = CONFIGURED_ORDERED_FILTERS.get(order);
		if (oldFilter != null) {
			throw new IllegalArgumentException("Cannot register filter '" + beanName +
					"' at position " + order + "; '" + oldFilter +
					"' is already registered in that position");
		}

		Filter filter = getBean(beanName);
		CONFIGURED_ORDERED_FILTERS.put(order, filter);
		FilterChainProxy filterChain = getBean("springSecurityFilterChain");
		filterChain.setFilterChainMap(Collections.singletonMap(
				filterChain.getMatcher().getUniversalMatchPattern(),
				new ArrayList<Filter>(CONFIGURED_ORDERED_FILTERS.values())));
	}

	/**
	 * Check if the current user is switched to another user.
	 * @return  <code>true</code> if logged in and switched
	 */
	public static boolean isSwitched() {
		return ifAllGranted(SwitchUserFilter.ROLE_PREVIOUS_ADMINISTRATOR);
	}

	/**
	 * Get the username of the original user before switching to another.
	 * @return  the original login name
	 */
	public static String getSwitchedUserOriginalUsername() {
		if (isSwitched()) {
			Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
			for (GrantedAuthority auth : authentication.getAuthorities()) {
				if (auth instanceof SwitchUserGrantedAuthority) {
					return ((SwitchUserGrantedAuthority)auth).getSource().getName();
				}
			}
		}
		return null;
	}

	/**
	 * Lookup the security type as a String to avoid dev mode reload issues.
	 * @return the name of the <code>SecurityConfigType</code>
	 */
	public static String getSecurityConfigType() {
		return getSecurityConfig().get("securityConfigType").toString();
	}

	/**
	 * Rebuild an Authentication for the given username and register it in the security context.
	 * Typically used after updating a user's authorities or other auth-cached info.
	 * <p/>
	 * Also removes the user from the user cache to force a refresh at next login.
	 *
	 * @param username  the user's login name
	 * @param password  optional
	 */
	public static void reauthenticate(final String username, final String password) {
		UserDetailsService userDetailsService = getBean("userDetailsService");
		UserCache userCache = getBean("userCache");

		UserDetails userDetails = userDetailsService.loadUserByUsername(username);
		SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(
				userDetails, password == null ? userDetails.getPassword() : password, userDetails.getAuthorities()));
		userCache.removeUserFromCache(username);
	}

	/**
	 * Execute a closure with the current authentication. Assumes that there's an authentication in the
	 * http session and that the closure is running in a separate thread from the web request, so the
	 * context and authentication aren't available to the standard ThreadLocal.
	 *
	 * @param closure  the code to run
	 * @return  the closure's return value
	 */
	public static Object doWithAuth(final Closure closure) {
		boolean set = false;
		if (SecurityContextHolder.getContext().getAuthentication() == null) {
			HttpSession httpSession = SecurityRequestHolder.getRequest().getSession(false);
			SecurityContext context = null;
			if (httpSession != null) {
				context = (SecurityContext)httpSession.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
				if (context != null) {
					SecurityContextHolder.setContext(context);
					set = true;
				}
			}
		}

		try {
			return closure.call();
		}
		finally {
			if (set) {
				SecurityContextHolder.clearContext();
			}
		}
	}

	/**
	 * Authenticate as the specified user and execute the closure with that authentication. Restores
	 * the authentication to the one that was active if it exists, or clears the context otherwise.
	 * <p/>
	 * This is similar to run-as and switch-user but is only local to a Closure.
	 *
	 * @param username the username to authenticate as
	 * @param closure  the code to run
	 * @return  the closure's return value
	 */
	public static Object doWithAuth(final String username, final Closure closure) {
		Authentication previousAuth = SecurityContextHolder.getContext().getAuthentication();
		reauthenticate(username, null);

		try {
			return closure.call();
		}
		finally {
			if (previousAuth == null) {
				SecurityContextHolder.clearContext();
			}
			else {
				SecurityContextHolder.getContext().setAuthentication(previousAuth);
			}
		}
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

	private static Collection<GrantedAuthority> findInferredAuthorities(
			final Collection<GrantedAuthority> granted) {
		RoleHierarchy roleHierarchy = getBean("roleHierarchy");
		Collection<GrantedAuthority> reachable = roleHierarchy.getReachableGrantedAuthorities(granted);
		if (reachable == null) {
			return Collections.emptyList();
		}
		return reachable;
	}

	@SuppressWarnings("unchecked")
	private static  <T> T getBean(final String name) {
		return (T)ApplicationHolder.getApplication().getMainContext().getBean(name);
	}
}
