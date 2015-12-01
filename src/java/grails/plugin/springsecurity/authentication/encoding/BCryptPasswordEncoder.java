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
package grails.plugin.springsecurity.authentication.encoding;

import org.springframework.util.Assert;

/**
 * Wrapper for the Spring Security crypto version (different interface).
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
@SuppressWarnings("deprecation")
public class BCryptPasswordEncoder implements org.springframework.security.authentication.encoding.PasswordEncoder {

	protected final org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder delegate;

	/**
	 * Constructor.
	 * @param logRounds the log rounds to use
	 */
	public BCryptPasswordEncoder(int logRounds) {
		delegate = new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder(logRounds);
	}

	public String encodePassword(String rawPass, Object salt) {
		checkSalt(salt);
		return delegate.encode(rawPass);
	}

	public boolean isPasswordValid(String encPass, String rawPass, Object salt) {
		checkSalt(salt);
		return delegate.matches(rawPass, encPass);
	}

	protected void checkSalt(Object salt) {
		Assert.isNull(salt, "Salt value must be null when used with crypto module PasswordEncoder");
	}
}
