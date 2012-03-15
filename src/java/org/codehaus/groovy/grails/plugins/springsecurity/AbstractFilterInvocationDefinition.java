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

import grails.util.GrailsUtil;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.expression.Expression;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.vote.AuthenticatedVoter;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.expression.WebSecurityExpressionHandler;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.AntUrlPathMatcher;
import org.springframework.security.web.util.UrlMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
public abstract class AbstractFilterInvocationDefinition
       implements FilterInvocationSecurityMetadataSource, InitializingBean {

	private UrlMatcher _urlMatcher;
	private boolean _rejectIfNoRule;
	private boolean _stripQueryStringFromUrls = true;
	private RoleVoter _roleVoter;
	private AuthenticatedVoter _authenticatedVoter;
	private WebSecurityExpressionHandler _expressionHandler;

	private final Map<Object, Collection<ConfigAttribute>> _compiled = new LinkedHashMap<Object, Collection<ConfigAttribute>>();

	protected final Logger _log = LoggerFactory.getLogger(getClass());

	protected static final Collection<ConfigAttribute> DENY = Collections.emptyList();

	/**
	 * Allows subclasses to be externally reset.
	 * @throws Exception
	 */
	public void reset() throws Exception {
		// override if necessary
	}

	/**
	 * {@inheritDoc}
	 * @see org.springframework.security.access.SecurityMetadataSource#getAttributes(java.lang.Object)
	 */
	public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
		Assert.isTrue(object != null && supports(object.getClass()), "Object must be a FilterInvocation");

		FilterInvocation filterInvocation = (FilterInvocation)object;

		String url = determineUrl(filterInvocation);

		Collection<ConfigAttribute> configAttributes;
		try {
			configAttributes = findConfigAttributes(url);
		}
		catch (Exception e) {
			// TODO fix this
			throw new RuntimeException(e);
		}

		if (configAttributes == null && _rejectIfNoRule) {
			return DENY;
		}

		return configAttributes;
	}

	protected abstract String determineUrl(FilterInvocation filterInvocation);

	protected boolean stopAtFirstMatch() {
		return false;
	}

	private Collection<ConfigAttribute> findConfigAttributes(final String url) throws Exception {

		initialize();

		Collection<ConfigAttribute> configAttributes = null;
		Object configAttributePattern = null;

		boolean stopAtFirstMatch = stopAtFirstMatch();
		for (Map.Entry<Object, Collection<ConfigAttribute>> entry : _compiled.entrySet()) {
			Object pattern = entry.getKey();
			if (_urlMatcher.pathMatchesUrl(pattern, url)) {
				// TODO this assumes Ant matching, not valid for regex
				if (configAttributes == null || _urlMatcher.pathMatchesUrl(configAttributePattern, (String)pattern)) {
					configAttributes = entry.getValue();
					configAttributePattern = pattern;
					if (_log.isTraceEnabled()) {
						_log.trace("new candidate for '" + url + "': '" + pattern
								+ "':" + configAttributes);
					}
					if (stopAtFirstMatch) {
						break;
					}
				}
			}
		}

		if (_log.isTraceEnabled()) {
			if (configAttributes == null) {
				_log.trace("no config for '" + url + "'");
			}
			else {
				_log.trace("config for '" + url + "' is '" + configAttributePattern + "':" + configAttributes);
			}
		}

		return configAttributes;
	}

	protected void initialize() throws Exception {
		// override if necessary
	}

	/**
	 * {@inheritDoc}
	 * @see org.springframework.security.access.SecurityMetadataSource#supports(java.lang.Class)
	 */
	public boolean supports(Class<?> clazz) {
		return FilterInvocation.class.isAssignableFrom(clazz);
	}

	/**
	 * {@inheritDoc}
	 * @see org.springframework.security.access.SecurityMetadataSource#getAllConfigAttributes()
	 */
	public Collection<ConfigAttribute> getAllConfigAttributes() {
		try {
			initialize();
		}
		catch (Exception e) {
			GrailsUtil.deepSanitize(e);
			_log.error(e.getMessage(), e);
		}

		Collection<ConfigAttribute> all = new HashSet<ConfigAttribute>();
		for (Collection<ConfigAttribute> configs : _compiled.values()) {
			all.addAll(configs);
		}
		return Collections.unmodifiableCollection(all);
	}

	/**
	 * Dependency injection for the url matcher.
	 * @param urlMatcher the matcher
	 */
	public void setUrlMatcher(final UrlMatcher urlMatcher) {
		_urlMatcher = urlMatcher;
		_stripQueryStringFromUrls = _urlMatcher instanceof AntUrlPathMatcher;
	}

	/**
	 * Dependency injection for whether to reject if there's no matching rule.
	 * @param reject if true, reject access unless there's a pattern for the specified resource
	 */
	public void setRejectIfNoRule(final boolean reject) {
		_rejectIfNoRule = reject;
	}

	protected String lowercaseAndStripQuerystring(final String url) {

		String fixed = url;

		if (getUrlMatcher().requiresLowerCaseUrl()) {
			fixed = fixed.toLowerCase();
		}

		if (_stripQueryStringFromUrls) {
			int firstQuestionMarkIndex = fixed.indexOf("?");
			if (firstQuestionMarkIndex != -1) {
				fixed = fixed.substring(0, firstQuestionMarkIndex);
			}
		}

		return fixed;
	}

	protected UrlMatcher getUrlMatcher() {
		return _urlMatcher;
	}

	/**
	 * For debugging.
	 * @return an unmodifiable map of {@link AnnotationFilterInvocationDefinition}ConfigAttributeDefinition
	 * keyed by compiled patterns
	 */
	public Map<Object, Collection<ConfigAttribute>> getConfigAttributeMap() {
		return Collections.unmodifiableMap(_compiled);
	}

	// fixes extra spaces, trailing commas, etc.
	protected List<String> split(final String value) {
		if (!value.startsWith("ROLE_") && !value.startsWith("IS_")) {
			// an expression
			return Collections.singletonList(value);
		}

		String[] parts = StringUtils.commaDelimitedListToStringArray(value);
		List<String> cleaned = new ArrayList<String>();
		for (String part : parts) {
			part = part.trim();
			if (part.length() > 0) {
				cleaned.add(part);
			}
		}
		return cleaned;
	}

	protected void compileAndStoreMapping(final String pattern, final List<String> tokens) {

		Object key = getUrlMatcher().compile(pattern);

		Collection<ConfigAttribute> configAttributes = buildConfigAttributes(tokens);

		Collection<ConfigAttribute> replaced = storeMapping(key,
				Collections.unmodifiableCollection(configAttributes));
		if (replaced != null) {
			_log.warn("replaced rule for '" + key + "' with roles " + replaced +
					" with roles " + configAttributes);
		}
	}

	protected Collection<ConfigAttribute> buildConfigAttributes(final Collection<String> tokens) {
		Collection<ConfigAttribute> configAttributes = new HashSet<ConfigAttribute>();
		for (String token : tokens) {
			ConfigAttribute config = new SecurityConfig(token);
			if (supports(config)) {
				configAttributes.add(config);
			}
			else {
				Expression expression = _expressionHandler.getExpressionParser().parseExpression(token);
				configAttributes.add(new WebExpressionConfigAttribute(expression));
			}
		}
		return configAttributes;
	}

	protected boolean supports(final ConfigAttribute config) {
		return supports(config, _roleVoter) || supports(config, _authenticatedVoter) ||
				config.getAttribute().startsWith("RUN_AS");
	}

	private boolean supports(final ConfigAttribute config, final AccessDecisionVoter voter) {
		return voter != null && voter.supports(config);
	}

	protected Collection<ConfigAttribute> storeMapping(final Object key,
			final Collection<ConfigAttribute> configAttributes) {
		return _compiled.put(key, configAttributes);
	}

	protected void resetConfigs() {
		_compiled.clear();
	}

	/**
	 * For admin/debugging - find all config attributes that apply to the specified URL.
	 * @param url the URL
	 * @return matching attributes
	 */
	public Collection<ConfigAttribute> findMatchingAttributes(final String url) {
		for (Map.Entry<Object, Collection<ConfigAttribute>> entry : _compiled.entrySet()) {
			if (_urlMatcher.pathMatchesUrl(entry.getKey(), url)) {
				return entry.getValue();
			}
		}
		return Collections.emptyList();
	}

	/**
	 * Dependency injection for the role voter.
	 * @param voter the voter
	 */
	public void setRoleVoter(final RoleVoter voter) {
		_roleVoter = voter;
	}

	protected RoleVoter getRoleVoter() {
		return _roleVoter;
	}

	/**
	 * Dependency injection for the authenticated voter.
	 * @param voter the voter
	 */
	public void setAuthenticatedVoter(final AuthenticatedVoter voter) {
		_authenticatedVoter = voter;
	}
	protected AuthenticatedVoter getAuthenticatedVoter() {
		return _authenticatedVoter;
	}

	/**
	 * Dependency injection for the expression handler.
	 * @param handler the handler
	 */
	public void setExpressionHandler(final WebSecurityExpressionHandler handler) {
		_expressionHandler = handler;
	}
	protected WebSecurityExpressionHandler getExpressionHandler() {
		return _expressionHandler;
	}

	/**
	 * {@inheritDoc}
	 * @see org.springframework.beans.factory.InitializingBean#afterPropertiesSet()
	 */
	public void afterPropertiesSet() {
		Assert.notNull(_urlMatcher, "url matcher is required");
	}
}
