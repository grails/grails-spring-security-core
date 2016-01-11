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
package test

import groovy.transform.EqualsAndHashCode
import groovy.transform.ToString

@EqualsAndHashCode(includes=['series', 'username'])
@ToString(includes=['series', 'username'], cache=true, includeNames=true, includePackage=false)
class TestPersistentLogin implements Serializable {

	private static final long serialVersionUID = 1

	String series
	String username
	String token
	Date lastUsed

	static constraints = {
		series maxSize: 64
		token maxSize: 64
		username maxSize: 64
	}

	static mapping = {
		table 'persistent_login'
		id name: 'series', generator: 'assigned'
		version false
	}
}
