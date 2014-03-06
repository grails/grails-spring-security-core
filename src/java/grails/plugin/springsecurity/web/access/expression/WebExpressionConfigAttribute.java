/* Copyright 2006-2014 SpringSource.
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
package grails.plugin.springsecurity.web.access.expression;

import org.springframework.expression.Expression;
import org.springframework.security.access.ConfigAttribute;

/**
 * Simple expression configuration attribute for use in web request authorizations.
 * Based on the class of the same name in Spring Security which is package-default.
 *
 * @author Luke Taylor
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
public class WebExpressionConfigAttribute implements ConfigAttribute {

	private static final long serialVersionUID = 1;

	protected final Expression expression;

	/**
	 * Constructor.
	 * @param authorizeExpression the expression
	 */
	public WebExpressionConfigAttribute(final Expression authorizeExpression) {
		expression = authorizeExpression;
	}

	/**
	 * Accessor for the expression.
	 * @return the expression
	 */
	public Expression getAuthorizeExpression() {
		return expression;
	}

	/**
	 * {@inheritDoc}
	 * @see org.springframework.security.access.ConfigAttribute#getAttribute()
	 */
	public String getAttribute() {
		return null;
	}

	@Override
	public String toString() {
		return expression.getExpressionString();
	}
}
