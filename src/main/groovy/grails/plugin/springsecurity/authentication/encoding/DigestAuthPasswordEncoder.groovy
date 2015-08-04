/* Copyright 2006-2015 the original author or authors.
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
package grails.plugin.springsecurity.authentication.encoding

import java.security.MessageDigest
import java.security.NoSuchAlgorithmException

import org.springframework.beans.factory.InitializingBean
import org.springframework.security.crypto.codec.Hex

import groovy.transform.CompileStatic

/**
 * Workaround for the limitation in Digest authentication where you must store passwords in
 * the database in cleartext so the encrypted password use for comparison with what the
 * browser sends will agree. This password encoder uses the same algorithm as the browser
 * and does a good job with encryption (it effectively uses the username and the Realm
 * name as a salt) but is completely unconfigurable.
 *
 * Uses code from package org.springframework.security.web.authentication.www.DigestAuthUtils
 * which is unfortunately package-default.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
@CompileStatic
@SuppressWarnings('deprecation')
class DigestAuthPasswordEncoder implements org.springframework.security.authentication.encoding.PasswordEncoder, InitializingBean {

	protected boolean initializing = true

	/** Dependency injection for the realm name. */
	String realm

	String encodePassword(String rawPass, salt) {
		String username
		if (initializing && 'userNotFoundPassword' == rawPass) {
			// during startup, DaoAuthenticationProvider calls this method with a null salt
			username = rawPass
		}
		else {
			assert salt, 'Salt is required and must be the username'
			username = salt.toString()
		}

		md5Hex(username + ':' + realm + ':' + rawPass)
	}

	boolean isPasswordValid(String encPass, String rawPass, salt) {
		// the 'raw' password will already be encrypted, so compare directly
		encPass != null && rawPass != null ? rawPass == encPass : false
	}

	/**
	 * Called after the ApplicationContext is built to enable standard behavior.
	 */
	void resetInitializing() {
		initializing = false
	}

	void afterPropertiesSet() {
		assert realm, 'realm is required'
	}

	protected String md5Hex(String s) {
		try {
			new String(Hex.encode(MessageDigest.getInstance('MD5').digest(s.bytes)))
		}
		catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException('No MD5 algorithm available!')
		}
	}
}
