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

import org.springframework.expression.EvaluationContext;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.expression.ExpressionUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.expression.WebSecurityExpressionHandler;
import org.springframework.util.Assert;

/**
 * Based on the class of the same name in Spring Security which uses the
 * package-default WebExpressionConfigAttribute.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
public class WebExpressionVoter implements AccessDecisionVoter {

	private WebSecurityExpressionHandler _expressionHandler;

	/**
	 * {@inheritDoc}
	 * @see org.springframework.security.access.AccessDecisionVoter#vote(
	 * 	org.springframework.security.core.Authentication, java.lang.Object, java.util.Collection)
	 */
	public int vote(final Authentication authentication, final Object object,
			final Collection<ConfigAttribute> attributes) {

		Assert.notNull(authentication, "authentication cannot be null");
		Assert.notNull(object, "object cannot be null");
		Assert.notNull(attributes, "attributes cannot be null");

		WebExpressionConfigAttribute weca = findConfigAttribute(attributes);
		if (weca == null) {
			return ACCESS_ABSTAIN;
		}

		FilterInvocation fi = (FilterInvocation)object;
		EvaluationContext ctx = _expressionHandler.createEvaluationContext(authentication, fi);

		return ExpressionUtils.evaluateAsBoolean(weca.getAuthorizeExpression(), ctx) ?
				ACCESS_GRANTED : ACCESS_DENIED;
	}

	private WebExpressionConfigAttribute findConfigAttribute(final Collection<ConfigAttribute> attributes) {
		for (ConfigAttribute attribute : attributes) {
			if (attribute instanceof WebExpressionConfigAttribute) {
				return (WebExpressionConfigAttribute)attribute;
			}
		}
		return null;
	}

	/**
	 * {@inheritDoc}
	 * @see org.springframework.security.access.AccessDecisionVoter#supports(
	 * 	org.springframework.security.access.ConfigAttribute)
	 */
	public boolean supports(ConfigAttribute attribute) {
		return attribute instanceof WebExpressionConfigAttribute;
	}

	/**
	 * {@inheritDoc}
	 * @see org.springframework.security.access.AccessDecisionVoter#supports(java.lang.Class)
	 */
	public boolean supports(Class<?> clazz) {
		return clazz.isAssignableFrom(FilterInvocation.class);
	}

	/**
	 * Dependency injection for the expression handler.
	 * @param expressionHandler the handler
	 */
	public void setExpressionHandler(final WebSecurityExpressionHandler expressionHandler) {
		_expressionHandler = expressionHandler;
	}
}
