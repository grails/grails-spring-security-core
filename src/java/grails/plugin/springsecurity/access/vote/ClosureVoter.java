/* Copyright 2013 SpringSource.
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
package grails.plugin.springsecurity.access.vote;

import grails.plugin.springsecurity.annotation.SecuredClosureDelegate;
import groovy.lang.Closure;

import java.util.Collection;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;
import org.springframework.util.Assert;

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
public class ClosureVoter implements AccessDecisionVoter<FilterInvocation>, ApplicationContextAware {

	protected final Logger log = LoggerFactory.getLogger(getClass());

	protected ApplicationContext ctx;

	public int vote(Authentication authentication, FilterInvocation fi, Collection<ConfigAttribute> attributes) {
		Assert.notNull(authentication, "authentication cannot be null");
		Assert.notNull(fi, "object cannot be null");
		Assert.notNull(attributes, "attributes cannot be null");

		ClosureConfigAttribute attribute = null;
		for (ConfigAttribute a : attributes) {
			if (a instanceof ClosureConfigAttribute) {
				attribute = (ClosureConfigAttribute) a;
				break;
			}
		}

		if (attribute == null) {
			return ACCESS_ABSTAIN;
		}

		Closure<?> closure = (Closure<?>) attribute.getClosure().clone();
		closure.setDelegate(new SecuredClosureDelegate(authentication, fi, ctx));
		Object result = closure.call();
		if (result instanceof Boolean) {
			return ((Boolean)result) ? ACCESS_GRANTED : ACCESS_DENIED;
		}

		// TODO log warning
		return ACCESS_DENIED;
	}

	public boolean supports(ConfigAttribute attribute) {
		return attribute instanceof ClosureConfigAttribute;
	}

	public boolean supports(Class<?> clazz) {
		return clazz.isAssignableFrom(FilterInvocation.class);
	}

	public void setApplicationContext(ApplicationContext applicationContext) {
		ctx = applicationContext;
	}
}
