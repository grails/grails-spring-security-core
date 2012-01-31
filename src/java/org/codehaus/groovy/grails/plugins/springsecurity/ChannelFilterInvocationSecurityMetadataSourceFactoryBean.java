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

import java.util.Collection;
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
import org.springframework.util.Assert;

/**
 * Factory bean that builds a {@link FilterInvocationSecurityMetadataSource} for channel security.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
public class ChannelFilterInvocationSecurityMetadataSourceFactoryBean
       implements FactoryBean<FilterInvocationSecurityMetadataSource>, InitializingBean {

	private UrlMatcher _urlMatcher;
	private Map<String, String> _definition;
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
		Assert.notNull(_definition, "definition map is required");
		Assert.notNull(_urlMatcher, "urlMatcher is required");

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
	 * @param definition keys are URL patterns, values are ANY_CHANNEL, REQUIRES_SECURE_CHANNEL, or REQUIRES_INSECURE_CHANNEL
	 */
	public void setDefinition(Map<String, String> definition) {
		_definition = definition;
	}
}
