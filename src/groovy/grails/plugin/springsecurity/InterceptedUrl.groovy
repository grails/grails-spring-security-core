/* Copyright 2013-2014 SpringSource.
 *
 * Licensed under the Apache License, Version 2.0 (the "License")
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
package grails.plugin.springsecurity

import groovy.transform.EqualsAndHashCode
import groovy.transform.ToString

import org.springframework.http.HttpMethod
import org.springframework.security.access.ConfigAttribute

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
@EqualsAndHashCode(includes='pattern,access,httpMethod')
@ToString
class InterceptedUrl {
	String pattern
	Collection<ConfigAttribute> configAttributes = Collections.emptyList()
	HttpMethod httpMethod
	boolean filters = true
	Boolean https // true->https, false->http, null->any
	Class<?> closureClass

	InterceptedUrl(String pattern, Collection<String> tokens, HttpMethod httpMethod) {
		this.pattern = pattern
		this.configAttributes = ReflectionUtils.buildConfigAttributes(tokens)
		this.httpMethod = httpMethod
	}

	InterceptedUrl(String pattern, HttpMethod httpMethod, Collection<ConfigAttribute> configAttributes) {
		this.pattern = pattern
		this.httpMethod = httpMethod
		this.configAttributes = configAttributes
	}

	InterceptedUrl(String pattern, Class<?> closureClass, HttpMethod httpMethod) {
		this.pattern = pattern
		this.closureClass = closureClass
		this.httpMethod = httpMethod
	}
}
