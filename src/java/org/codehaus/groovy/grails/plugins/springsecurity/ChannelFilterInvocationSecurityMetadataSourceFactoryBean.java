package org.codehaus.groovy.grails.plugins.springsecurity;

import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.beans.factory.FactoryBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.RequestKey;
import org.springframework.security.web.util.UrlMatcher;

/**
 * Factory bean that builds a {@link FilterInvocationSecurityMetadataSource} for channel security.
 *
 * @author Burt
 */
public class ChannelFilterInvocationSecurityMetadataSourceFactoryBean
       implements FactoryBean<FilterInvocationSecurityMetadataSource>, InitializingBean {

	private UrlMatcher _urlMatcher;
	private Map<String, String> _definition = new HashMap<String, String>();
	private DefaultFilterInvocationSecurityMetadataSource _source;

	/**
	 * {@inheritDoc}
	 * @see org.springframework.beans.factory.FactoryBean#getObject()
	 */
	public FilterInvocationSecurityMetadataSource getObject() {
		return _source;
	}

	/**
	 * {@inheritDoc}
	 * @see org.springframework.beans.factory.FactoryBean#getObjectType()
	 */
	public Class<DefaultFilterInvocationSecurityMetadataSource> getObjectType() {
		return DefaultFilterInvocationSecurityMetadataSource.class;
	}

	/**
	 * {@inheritDoc}
	 * @see org.springframework.beans.factory.FactoryBean#isSingleton()
	 */
	public boolean isSingleton() {
		return true;
	}

	/**
	 * {@inheritDoc}
	 * @see org.springframework.beans.factory.InitializingBean#afterPropertiesSet()
	 */
	public void afterPropertiesSet() {
		_source = new DefaultFilterInvocationSecurityMetadataSource(_urlMatcher, buildMap());
	}

	protected LinkedHashMap<RequestKey, Collection<ConfigAttribute>> buildMap() {
		LinkedHashMap<RequestKey, Collection<ConfigAttribute>> map = new LinkedHashMap<RequestKey, Collection<ConfigAttribute>>();
		for (Map.Entry<String, String> entry : _definition.entrySet()) {
			String value = entry.getValue();
			if (value == null) {
				throw new IllegalArgumentException("The rule for URL '" + value + "' cannot be null");
			}
			value = value.trim();

			if (!"ANY_CHANNEL".equals(value) &&
					!"REQUIRES_SECURE_CHANNEL".equals(value) &&
					!"REQUIRES_INSECURE_CHANNEL".equals(value)) {
				throw new IllegalArgumentException("The rule for URL '" + value +
						"' must be one of REQUIRES_SECURE_CHANNEL, REQUIRES_INSECURE_CHANNEL, or ANY_CHANNEL");
			}

			map.put(new RequestKey(entry.getKey()),
					SecurityConfig.createSingleAttributeList(value));
		}
		return map;
	}

	/**
	 * Dependency injection for the url matcher.
	 *
	 * @param urlMatcher
	 */
	public void setUrlMatcher(final UrlMatcher urlMatcher) {
		_urlMatcher = urlMatcher;
	}

	/**
	 * Dependency injection for the definition map.
	 *
	 * @param definition  keys are URL patterns, values are ANY_CHANNEL, REQUIRES_SECURE_CHANNEL, or REQUIRES_INSECURE_CHANNEL
	 */
	public void setDefinition(Map<String, String> definition) {
		_definition = definition;
	}
}
