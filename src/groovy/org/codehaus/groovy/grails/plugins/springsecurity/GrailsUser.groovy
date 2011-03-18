/* Copyright 2006-2010 the original author or authors.
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
package org.codehaus.groovy.grails.plugins.springsecurity

import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.userdetails.User

/**
 * Extends the default Spring Security user class to contain the ID for efficient lookup
 * of the domain class from the Authentication.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class GrailsUser extends User {

	static final long serialVersionUID = 1L

	private final Object _id

	GrailsUser(String username, String password, boolean enabled, boolean accountNonExpired,
         boolean credentialsNonExpired, boolean accountNonLocked,
         Collection<GrantedAuthority> authorities, Object id) {
		super(username, password, enabled, accountNonExpired, credentialsNonExpired,
				accountNonLocked, authorities)
		_id = id
	}

	/**
	 * Get the id.
	 * @return  the id
	 */
	Object getId() { _id }
}
