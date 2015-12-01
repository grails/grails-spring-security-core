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
package grails.plugin.springsecurity;

import grails.plugin.springsecurity.web.SecurityRequestHolder;
import grails.plugin.springsecurity.web.filter.DebugFilter;
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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;

import javax.servlet.Filter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.apache.commons.lang.StringEscapeUtils;
import org.codehaus.groovy.grails.commons.GrailsApplication;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
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
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartHttpServletRequest;

/**
 * Helper methods.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
public final class SpringSecurityUtils {

	private static final Logger LOG = LoggerFactory.getLogger(SpringSecurityUtils.class);

	private static ConfigObject _securityConfig;
	private static GrailsApplication application;

	private static List<String> providerNames = new ArrayList<String>();
	private static List<String> logoutHandlerNames = new ArrayList<String>();
	private static List<String> voterNames = new ArrayList<String>();
	private static List<String> afterInvocationManagerProviderNames = new ArrayList<String>();
	private static Map<Integer, String> orderedFilters = new HashMap<Integer, String>();
	private static SortedMap<Integer, Filter> configuredOrderedFilters = new TreeMap<Integer, Filter>();

	// HttpSessionRequestCache.SAVED_REQUEST is package-scope
	public static final String SAVED_REQUEST = "SPRING_SECURITY_SAVED_REQUEST"; // TODO use requestCache

	// UsernamePasswordAuthenticationFilter.SPRING_SECURITY_LAST_USERNAME_KEY is deprecated
	public static final String SPRING_SECURITY_LAST_USERNAME_KEY = "SPRING_SECURITY_LAST_USERNAME";

	// AbstractAuthenticationTargetUrlRequestHandler.DEFAULT_TARGET_PARAMETER was removed
	public static final String DEFAULT_TARGET_PARAMETER = "spring-security-redirect";

	/**
	 * Default value for the name of the Ajax header.
	 */
	public static final String AJAX_HEADER = "X-Requested-With";

	/**
	 * Used to ensure that all authenticated users have at least one granted authority to work
	 * around Spring Security code that assumes at least one. By granting this non-authority,
	 * the user can't do anything but gets past the somewhat arbitrary restrictions.
	 */
	public static final String NO_ROLE = "ROLE_NO_ROLES";

	private SpringSecurityUtils() {
		// static only
	}

	/**
	 * Set at startup by plugin.
	 * @param app the application
	 */
	public static void setApplication(GrailsApplication app) {
		application = app;
		initializeContext();
	}

	/**
	 * Extract the role names from authorities.
	 * @param authorities the authorities (a collection or array of {@link GrantedAuthority}).
	 * @return the names
	 */
	public static Set<String> authoritiesToRoles(final Object authorities) {
		Set<String> roles = new HashSet<String>();
		for (Object authority : ReflectionUtils.asList(authorities)) {
			String authorityName = ((GrantedAuthority)authority).getAuthority();
			if (null == authorityName) {
				throw new IllegalArgumentException(
						"Cannot process GrantedAuthority objects which return null " +
						"from getAuthority() - attempting to process " + authority);
			}
			roles.add(authorityName);
		}

		return roles;
	}

	/**
	 * Get the current user's authorities.
	 * @return a list of authorities (empty if not authenticated).
	 */
	public static Collection<GrantedAuthority> getPrincipalAuthorities() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication == null) {
			return Collections.emptyList();
		}

		Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
		if (authorities == null) {
			return Collections.emptyList();
		}

		// remove the fake role if it's there
		Collection<GrantedAuthority> copy = new ArrayList<GrantedAuthority>(authorities);
		for (Iterator<GrantedAuthority> iter = copy.iterator(); iter.hasNext();) {
			if (NO_ROLE.equals(iter.next().getAuthority())) {
				iter.remove();
			}
		}

		return copy;
	}

	/**
	 * Split the role names and create {@link GrantedAuthority}s for each.
	 * @param roleNames comma-delimited role names
	 * @return authorities (possibly empty)
	 */
	public static List<GrantedAuthority> parseAuthoritiesString(final String roleNames) {
		List<GrantedAuthority> requiredAuthorities = new ArrayList<GrantedAuthority>();
		for (String auth : StringUtils.commaDelimitedListToStringArray(roleNames)) {
			auth = auth.trim();
			if (auth.length() > 0) {
				requiredAuthorities.add(new SimpleGrantedAuthority(auth));
			}
		}

		return requiredAuthorities;
	}

	/**
	 * Find authorities in <code>granted</code> that are also in <code>required</code>.
	 * @param granted the granted authorities (a collection or array of {@link SpringSecurityUtils}).
	 * @param required the required authorities (a collection or array of {@link SpringSecurityUtils}).
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
	 * @param roles a comma-delimited list of role names
	 * @return <code>true</code> if the user is authenticated and has all the roles
	 */
	public static boolean ifAllGranted(final String roles) {
		return ifAllGranted(parseAuthoritiesString(roles));
 	}

	public static boolean ifAllGranted(final Collection<? extends GrantedAuthority> roles) {
		Set<String> inferredNames = authoritiesToRoles(findInferredAuthorities(getPrincipalAuthorities()));
		return inferredNames.containsAll(authoritiesToRoles(roles));
	}

	/**
	 * Check if the current user has none of the specified roles.
	 * @param roles a comma-delimited list of role names
	 * @return <code>true</code> if the user is authenticated and has none the roles
	 */
	public static boolean ifNotGranted(final String roles) {
		return ifNotGranted(parseAuthoritiesString(roles));
	}

	public static boolean ifNotGranted(final Collection<? extends GrantedAuthority> roles) {
		Collection<? extends GrantedAuthority> inferred = findInferredAuthorities(getPrincipalAuthorities());
		Set<String> grantedCopy = retainAll(inferred, roles);
		return grantedCopy.isEmpty();
	}

	/**
	 * Check if the current user has any of the specified roles.
	 * @param roles a comma-delimited list of role names
	 * @return <code>true</code> if the user is authenticated and has any the roles
	 */
	public static boolean ifAnyGranted(final String roles) {
		return ifAnyGranted(parseAuthoritiesString(roles));
	}

	public static boolean ifAnyGranted(final Collection<? extends GrantedAuthority> roles) {
		Collection<? extends GrantedAuthority> inferred = findInferredAuthorities(getPrincipalAuthorities());
		Set<String> grantedCopy = retainAll(inferred, roles);
		return !grantedCopy.isEmpty();
	}

	/**
	 * Parse and load the security configuration.
	 * @return the configuration
	 */
	public static synchronized ConfigObject getSecurityConfig() {
		if (_securityConfig == null) {
			LOG.trace("Building security config since there is no cached config");
			reloadSecurityConfig();
		}

		return _securityConfig;
	}

	/**
	 * For testing only.
	 * @param config the config
	 */
	public static void setSecurityConfig(ConfigObject config) {
		_securityConfig = config;
	}

	/**
	 * Reset the config for testing or after a dev mode Config.groovy change.
	 */
	public static synchronized void resetSecurityConfig() {
		_securityConfig = null;
		LOG.trace("reset security config");
	}

	/**
	 * Allow a secondary plugin to add config attributes.
	 * @param className the name of the config class.
	 */
	public static synchronized void loadSecondaryConfig(final String className) {
		mergeConfig(getSecurityConfig(), className);
		LOG.trace("loaded secondary config {}", className);
	}

	/**
	 * Force a reload of the security configuration.
	 */
	public static void reloadSecurityConfig() {
		mergeConfig(ReflectionUtils.getSecurityConfig(), "DefaultSecurityConfig");
		LOG.trace("reloaded security config");
	}

	/**
	 * Check if the request was triggered by an Ajax call.
	 * @param request the request
	 * @return <code>true</code> if Ajax
	 */
	public static boolean isAjax(final HttpServletRequest request) {

		String ajaxHeaderName = (String)ReflectionUtils.getConfigProperty("ajaxHeader");

		String xmlHttpRequest = "XMLHttpRequest";

		// check the current request's headers
		if (xmlHttpRequest.equals(request.getHeader(ajaxHeaderName))) {
			return true;
		}

		Object ajaxCheckClosure = ReflectionUtils.getConfigProperty("ajaxCheckClosure");
		if (ajaxCheckClosure instanceof Closure) {
			Object result = ((Closure<?>)ajaxCheckClosure).call(request);
			if (result instanceof Boolean && ((Boolean)result)) {
				return true;
			}
		}

		// look for an ajax=true parameter
		if ("true".equals(request.getParameter("ajax"))) {
			return true;
		}

		// process multipart requests
		MultipartHttpServletRequest multipart = ((MultipartHttpServletRequest)request.getAttribute("org.springframework.web.multipart.MultipartHttpServletRequest"));
		if (multipart != null && "true".equals(multipart.getParameter("ajax"))) {
			return true;
		}

		// check the SavedRequest's headers
		HttpSession httpSession = request.getSession(false);
		if (httpSession != null) {
			SavedRequest savedRequest = (SavedRequest)httpSession.getAttribute(SAVED_REQUEST);
			if (savedRequest != null) {
				return savedRequest.getHeaderValues(ajaxHeaderName).contains(xmlHttpRequest);
			}
		}

		return false;
	}

	/**
	 * Register a provider bean name.
	 * <p/>
	 * Note - only for use by plugins during bean building.
	 *
	 * @param beanName the Spring bean name of the provider
	 */
	public static void registerProvider(final String beanName) {
		providerNames.add(0, beanName);
		LOG.trace("Registered bean '{}' as a provider", beanName);
	}

	/**
	 * Authentication provider names. Plugins add or remove them, and can be overridden by config.
	 * @return the names
	 */
	public static List<String> getProviderNames() {
		return providerNames;
	}

	/**
	 * Register a logout handler bean name.
	 * <p/>
	 * Note - only for use by plugins during bean building.
	 *
	 * @param beanName the Spring bean name of the handler
	 */
	public static void registerLogoutHandler(final String beanName) {
		logoutHandlerNames.add(0, beanName);
		LOG.trace("Registered bean '{}' as a logout handler", beanName);
	}

	/**
	 * Logout handler names. Plugins add or remove them, and can be overridden by config.
	 * @return the names
	 */
	public static List<String> getLogoutHandlerNames() {
		return logoutHandlerNames;
	}

	/**
	 * Register an AfterInvocationProvider bean name.
	 * <p/>
	 * Note - only for use by plugins during bean building.
	 *
	 * @param beanName the Spring bean name of the provider
	 */
	public static void registerAfterInvocationProvider(final String beanName) {
		afterInvocationManagerProviderNames.add(0, beanName);
		LOG.trace("Registered bean '{}' as an AfterInvocationProvider", beanName);
	}

	/**
	 * AfterInvocationProvider names. Plugins add or remove them, and can be overridden by config.
	 * @return the names
	 */
	public static List<String> getAfterInvocationManagerProviderNames() {
		return afterInvocationManagerProviderNames;
	}

	/**
	 * Register a voter bean name.
	 * <p/>
	 * Note - only for use by plugins during bean building.
	 *
	 * @param beanName the Spring bean name of the voter
	 */
	public static void registerVoter(final String beanName) {
		voterNames.add(0, beanName);
		LOG.trace("Registered bean '{}' as a voter", beanName);
	}

	/**
	 * Voter names. Plugins add or remove them and can be overridden by config.
	 * @return the names
	 */
	public static List<String> getVoterNames() {
		return voterNames;
	}

	/**
	 * Register a filter bean name in a specified position in the chain.
	 * <p/>
	 * Note - only for use by plugins during bean building - to register at runtime
	 * (preferably in BootStrap) use <code>clientRegisterFilter</code>.
	 *
	 * @param beanName the Spring bean name of the filter
	 * @param order the position
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
	 * @param beanName the Spring bean name of the filter
	 * @param order the position (see {@link SecurityFilterPosition})
	 */
	public static void registerFilter(final String beanName, final int order) {
		String oldName = getOrderedFilters().get(order);
		if (oldName != null) {
			throw new IllegalArgumentException("Cannot register filter '" + beanName +
					"' at position " + order + "; '" + oldName +
					"' is already registered in that position");
		}
		getOrderedFilters().put(order, beanName);

		LOG.trace("Registered bean '{}' as a filter at order {}", beanName, order);
	}

	/**
	 * Ordered filter names. Plugins add or remove them, and can be overridden by config.
	 * @return the names
	 */
	public static Map<Integer, String> getOrderedFilters() {
		return orderedFilters;
	}

	/**
	 * Register a filter in a specified position in the chain.
	 * <p/>
	 * Note - this is for use in application code after the plugin has initialized,
	 * e.g. in BootStrap where you want to register a custom filter in the correct
	 * order without dealing with the existing configured filters.
	 *
	 * @param beanName the Spring bean name of the filter
	 * @param order the position
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
	 * @param beanName the Spring bean name of the filter
	 * @param order the position (see {@link SecurityFilterPosition})
	 */
	@SuppressWarnings("deprecation")
	public static void clientRegisterFilter(final String beanName, final int order) {
		Map<Integer, Filter> orderedFilters = SpringSecurityUtils.getConfiguredOrderedFilters();

		Filter oldFilter = orderedFilters.get(order);
		if (oldFilter != null) {
			throw new IllegalArgumentException("Cannot register filter '" + beanName + "' at position " + order + "; '"
					+ oldFilter + "' is already registered in that position");
		}

		Filter filter = getBean(beanName);
		orderedFilters.put(order, filter);

		FilterChainProxy filterChain = getFilterChainProxy();

		Map<RequestMatcher, List<Filter>> filterChainMap = filterChain.getFilterChainMap();
		Map<RequestMatcher, List<Filter>> fixedFilterChainMap = mergeFilterChainMap(orderedFilters, filter, order,
				filterChainMap);

		filterChain.setFilterChainMap(fixedFilterChainMap);

		LOG.trace("Client registered bean '{}' as a filter at order {}", beanName, order);
		LOG.trace("Updated filter chain: {}", fixedFilterChainMap);
	}

	private static FilterChainProxy getFilterChainProxy() {
		FilterChainProxy filterChain;
		Object bean = getBean("springSecurityFilterChain");
		if (bean instanceof DebugFilter) {
			filterChain = ((DebugFilter)bean).getFilterChainProxy();
		}
		else {
			filterChain = (FilterChainProxy)bean;
		}
		return filterChain;
	}

	private static Map<RequestMatcher, List<Filter>> mergeFilterChainMap(Map<Integer, Filter> orderedFilters,
			Filter filter, final int order, Map<RequestMatcher, List<Filter>> filterChainMap) {
		Map<Filter, Integer> filterToPosition = new HashMap<Filter, Integer>();
		for (Map.Entry<Integer, Filter> entry : orderedFilters.entrySet()) {
			filterToPosition.put(entry.getValue(), entry.getKey());
		}
		Map<RequestMatcher, List<Filter>> fixedFilterChainMap = new LinkedHashMap<RequestMatcher, List<Filter>>();
		for (Entry<RequestMatcher, List<Filter>> entry : filterChainMap.entrySet()) {
			List<Filter> filters = new ArrayList<Filter>(entry.getValue());
			int indexOfFilterBeforeTargetFilter = 0;
			while (indexOfFilterBeforeTargetFilter < filters.size()
					&& filterToPosition.get(filters.get(indexOfFilterBeforeTargetFilter)) < order) {
				indexOfFilterBeforeTargetFilter++;
			}
			filters.add(indexOfFilterBeforeTargetFilter, filter);
			fixedFilterChainMap.put(entry.getKey(), filters);
		}
		return fixedFilterChainMap;
	}

	/**
	 * Set by SpringSecurityCoreGrailsPlugin; contains the actual filter beans in order.
	 * @return the filters
	 */
	public static SortedMap<Integer, Filter> getConfiguredOrderedFilters() {
		return configuredOrderedFilters;
	}

	/**
	 * Check if the current user is switched to another user.
	 * @return <code>true</code> if logged in and switched
	 */
	public static boolean isSwitched() {
		Collection<? extends GrantedAuthority> inferred = findInferredAuthorities(getPrincipalAuthorities());
		for (GrantedAuthority authority : inferred) {
			if (authority instanceof SwitchUserGrantedAuthority) {
				return true;
			}
			if (SwitchUserFilter.ROLE_PREVIOUS_ADMINISTRATOR.equals(authority.getAuthority())) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Get the username of the original user before switching to another.
	 * @return the original login name
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
	 * @param username the user's login name
	 * @param password optional
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
	 * @param closure the code to run
	 * @return the closure's return value
	 */
	public static Object doWithAuth(@SuppressWarnings("rawtypes") final Closure closure) {
		boolean set = false;
		if (SecurityContextHolder.getContext().getAuthentication() == null && SecurityRequestHolder.getRequest() != null) {
			HttpSession httpSession = SecurityRequestHolder.getRequest().getSession(false);
			SecurityContext securityContext = null;
			if (httpSession != null) {
				securityContext = (SecurityContext)httpSession.getAttribute(
						HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
				if (securityContext != null) {
					SecurityContextHolder.setContext(securityContext);
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
	 * @param closure the code to run
	 * @return the closure's return value
	 */
	public static Object doWithAuth(final String username, @SuppressWarnings("rawtypes") final Closure closure) {
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

	public static SecurityContext getSecurityContext(final HttpSession session) {
		Object securityContext = session.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
		if (securityContext instanceof SecurityContext) {
			return (SecurityContext)securityContext;
		}
		return null;
	}

	/**
	 * Get the last auth exception.
	 * @param session the session
	 * @return the exception
	 */
	public static Throwable getLastException(final HttpSession session) {
		return (Throwable)session.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
	}

	/**
	 * Get the last attempted username.
	 * @param session the session
	 * @return the username
	 */
	public static String getLastUsername(final HttpSession session) {
		String username = (String)session.getAttribute(SPRING_SECURITY_LAST_USERNAME_KEY);
		if (username != null) {
			username = StringEscapeUtils.unescapeHtml(username);
		}
		return username;
	}

	/**
	 * Get the saved request from the session.
	 * @param session the session
	 * @return the saved request
	 */
	public static SavedRequest getSavedRequest(final HttpSession session) {
		return (SavedRequest)session.getAttribute(SAVED_REQUEST);
	}

	/**
	 * Merge in a secondary config (provided by a plugin as defaults) into the main config.
	 * @param currentConfig the current configuration
	 * @param className the name of the config class to load
	 */
	private static void mergeConfig(final ConfigObject currentConfig, final String className) {
		GroovyClassLoader classLoader = new GroovyClassLoader(SpringSecurityUtils.class.getClassLoader());
		ConfigSlurper slurper = new ConfigSlurper(Environment.getCurrent().getName());
		ConfigObject secondaryConfig;
		try {
			secondaryConfig = slurper.parse(classLoader.loadClass(className));
		}
		catch (ClassNotFoundException e) {
			throw new RuntimeException(e);
		}

		_securityConfig = mergeConfig(currentConfig, (ConfigObject)secondaryConfig.getProperty("security"));
		ReflectionUtils.setSecurityConfig(_securityConfig);
	}

	/**
	 * Merge two configs together. The order is important; if <code>secondary</code> is not null then
	 * start with that and merge the main config on top of that. This lets the <code>secondary</code>
	 * config act as default values but let user-supplied values in the main config override them.
	 *
	 * @param currentConfig the main config, starting from Config.groovy
	 * @param secondary new default values
	 * @return the merged configs
	 */
	private static ConfigObject mergeConfig(final ConfigObject currentConfig, final ConfigObject secondary) {
		ConfigObject config = new ConfigObject();
		if (secondary == null) {
			if (currentConfig != null) {
				config.putAll(currentConfig);
			}
		}
		else {
			if (currentConfig == null) {
				config.putAll(secondary);
			}
			else {
				config.putAll(secondary.merge(currentConfig));
			}
		}
		return config;
	}

	private static Collection<? extends GrantedAuthority> findInferredAuthorities(
			final Collection<GrantedAuthority> granted) {
		RoleHierarchy roleHierarchy = getBean("roleHierarchy");
		Collection<? extends GrantedAuthority> reachable = roleHierarchy.getReachableGrantedAuthorities(granted);
		if (reachable == null) {
			return Collections.emptyList();
		}
		return reachable;
	}

	@SuppressWarnings("unchecked")
	private static <T> T getBean(final String name) {
		return (T)application.getMainContext().getBean(name);
	}

	/**
	 * Called each time doWithApplicationContext() is invoked, so it's important to reset
	 * to default values when running integration and functional tests together.
	 */
	private static void initializeContext() {
		voterNames.clear();
		voterNames.add("authenticatedVoter");
		voterNames.add("roleVoter");
		voterNames.add("webExpressionVoter");
		voterNames.add("closureVoter");

		logoutHandlerNames.clear();
		logoutHandlerNames.add("rememberMeServices");
		logoutHandlerNames.add("securityContextLogoutHandler");

		providerNames.clear();
		providerNames.add("daoAuthenticationProvider");
		providerNames.add("anonymousAuthenticationProvider");
		providerNames.add("rememberMeAuthenticationProvider");

		orderedFilters.clear();

		configuredOrderedFilters.clear();

		afterInvocationManagerProviderNames.clear();
	}
}
