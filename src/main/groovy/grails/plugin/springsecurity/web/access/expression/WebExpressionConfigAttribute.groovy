/* Copyright 2006-2016 the original author or authors.
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
package grails.plugin.springsecurity.web.access.expression

import org.springframework.expression.Expression
import org.springframework.security.access.ConfigAttribute

import groovy.transform.CompileStatic

/**
 * Simple expression configuration attribute for use in web request authorizations.
 * Based on the class of the same name in Spring Security which is package-default.
 *
 * @author Luke Taylor
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
@CompileStatic
class WebExpressionConfigAttribute implements ConfigAttribute {

	private static final long serialVersionUID = 1

	final Expression authorizeExpression

	/**
	 * Constructor.
	 * @param authorizeExpression the expression
	 */
	WebExpressionConfigAttribute(Expression authorizeExpression) {
		this.authorizeExpression = authorizeExpression
	}

	String getAttribute() {}

	@Override
	String toString() {
		authorizeExpression.expressionString
	}
}
