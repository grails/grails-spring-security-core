/* Copyright 2012-2015 the original author or authors.
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
package grails.plugin.springsecurity.web.access.channel

import javax.servlet.ServletException

import org.springframework.security.access.ConfigAttribute
import org.springframework.security.web.FilterInvocation
import org.springframework.security.web.access.channel.InsecureChannelProcessor

import groovy.transform.CompileStatic

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
@CompileStatic
class HeaderCheckInsecureChannelProcessor extends InsecureChannelProcessor {

	/** The name of the header to check. */
	String headerName

	/** The header value to trigger a redirect. */
	String headerValue

	@Override
	void decide(FilterInvocation invocation, Collection<ConfigAttribute> config) throws IOException, ServletException {

		assert invocation && config != null, 'Nulls cannot be provided'

		for (ConfigAttribute attribute in config) {
			if (supports(attribute)) {
				if (headerValue == invocation.httpRequest.getHeader(headerName)) {
					entryPoint.commence invocation.request, invocation.response
				}
			}
		}
	}

	@Override
	void afterPropertiesSet() {
		super.afterPropertiesSet()
		assert headerName, 'Header name is required'
		assert headerValue, 'Header value is required'
	}
}
