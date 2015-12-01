/* Copyright 2013-2015 the original author or authors.
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

import groovy.lang.Closure;

import org.springframework.security.access.ConfigAttribute;

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
public class ClosureConfigAttribute implements ConfigAttribute {

	private static final long serialVersionUID = 1;

	protected final Closure<?> closure;

	/**
	 * Constructor.
	 * @param authorizeExpression the expression
	 */
	public ClosureConfigAttribute(final Closure<?> closure) {
		this.closure = closure;
	}

	/**
	 * Accessor for the closure.
	 * @return the closure
	 */
	public Closure<?> getClosure() {
		return closure;
	}

	public String getAttribute() {
		return null;
	}
}
