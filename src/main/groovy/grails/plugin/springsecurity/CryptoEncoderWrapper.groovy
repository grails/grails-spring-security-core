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
package grails.plugin.springsecurity

import groovy.transform.CompileStatic

/**
 * Converts a org.springframework.security.crypto.password.PasswordEncoder to a
 * org.springframework.security.authentication.encoding.PasswordEncoder.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
@SuppressWarnings('deprecation')
@CompileStatic
class CryptoEncoderWrapper implements org.springframework.security.authentication.encoding.PasswordEncoder {

	protected final org.springframework.security.crypto.password.PasswordEncoder delegateEncoder

	/**
	 * @param encoder
	 */
	CryptoEncoderWrapper(org.springframework.security.crypto.password.PasswordEncoder encoder) {
		delegateEncoder = encoder
	}

	String encodePassword(String rawPass, salt) {
		checkSalt salt
		delegateEncoder.encode rawPass
	}

	boolean isPasswordValid(String encPass, String rawPass, salt) {
		checkSalt salt
		delegateEncoder.matches rawPass, encPass
	}

	protected void checkSalt(salt) {
		assert salt == null, 'Salt value must be null when used with crypto module PasswordEncoder'
	}
}
