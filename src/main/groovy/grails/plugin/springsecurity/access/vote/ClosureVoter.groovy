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
package grails.plugin.springsecurity.access.vote

import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.context.ApplicationContext
import org.springframework.context.ApplicationContextAware
import org.springframework.security.access.AccessDecisionVoter
import org.springframework.security.access.ConfigAttribute
import org.springframework.security.core.Authentication
import org.springframework.security.web.FilterInvocation

import grails.plugin.springsecurity.annotation.SecuredClosureDelegate
import groovy.transform.CompileStatic

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
@CompileStatic
class ClosureVoter implements AccessDecisionVoter<FilterInvocation>, ApplicationContextAware {

	protected final Logger log = LoggerFactory.getLogger(getClass())

	ApplicationContext applicationContext

	int vote(Authentication authentication, FilterInvocation fi, Collection<ConfigAttribute> attributes) {
		assert authentication, 'authentication cannot be null'
		assert fi, 'object cannot be null'
		assert attributes != null, 'attributes cannot be null'

		ClosureConfigAttribute attribute = (ClosureConfigAttribute)attributes.find { it instanceof ClosureConfigAttribute }

		if (!attribute) {
			return ACCESS_ABSTAIN
		}

		Closure<?> closure = (Closure<?>) attribute.closure.clone()
		closure.delegate = new SecuredClosureDelegate(authentication, fi, applicationContext)
		def result = closure.call()
		if (result instanceof Boolean) {
			return result ? ACCESS_GRANTED : ACCESS_DENIED
		}

		// TODO log warning
		ACCESS_DENIED
	}

	boolean supports(ConfigAttribute attribute) {
		attribute instanceof ClosureConfigAttribute
	}

	boolean supports(Class<?> clazz) {
		clazz.isAssignableFrom FilterInvocation
	}
}
