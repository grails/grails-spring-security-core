/* Copyright 2006-2015 SpringSource.
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
package test

import groovy.transform.ToString

import org.apache.commons.lang.builder.HashCodeBuilder
import org.springframework.http.HttpMethod

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
@ToString(cache=true, includeNames=true, includePackage=false)
class TestRequestmap implements Serializable {

	private static final long serialVersionUID = 1

	String urlPattern
	String rolePattern
	HttpMethod httpMethod

	TestRequestmap(String urlPattern, String rolePattern, HttpMethod httpMethod = null) {
		this()
		this.rolePattern = rolePattern
		this.httpMethod = httpMethod
		this.urlPattern = urlPattern
	}

	@Override
	int hashCode() {
		new HashCodeBuilder().append(rolePattern).append(httpMethod).append(urlPattern).toHashCode()
	}

	@Override
	boolean equals(other) {
		is(other) || (
			other instanceof TestRequestmap &&
			other.rolePattern == rolePattern &&
			other.httpMethod == httpMethod &&
			other.urlPattern == urlPattern)
	}

	static constraints = {
		rolePattern blank: false
		httpMethod nullable: true
		urlPattern blank: false, unique: 'httpMethod'
	}

	static mapping = {
		cache true
	}
}
