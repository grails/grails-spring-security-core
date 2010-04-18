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
package org.codehaus.groovy.grails.plugins.springsecurity;

/**
 * Stores the default order numbers of all Spring Security filters for use in configuration.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
public enum SecurityFilterPosition {
	FIRST(Integer.MIN_VALUE),
	CHANNEL_FILTER,
	CONCURRENT_SESSION_FILTER,
	SECURITY_CONTEXT_FILTER,
	LOGOUT_FILTER,
	X509_FILTER,
	PRE_AUTH_FILTER,
	CAS_FILTER,
	FORM_LOGIN_FILTER,
	OPENID_FILTER,
	LOGIN_PAGE_FILTER,
	DIGEST_AUTH_FILTER,
	BASIC_AUTH_FILTER,
	REQUEST_CACHE_FILTER,
	SERVLET_API_SUPPORT_FILTER,
	REMEMBER_ME_FILTER,
	ANONYMOUS_FILTER,
	SESSION_MANAGEMENT_FILTER,
	EXCEPTION_TRANSLATION_FILTER,
	FILTER_SECURITY_INTERCEPTOR,
	SWITCH_USER_FILTER,
	LAST(Integer.MAX_VALUE);

	private static final int INTERVAL = 100;
	private final int _order;

	private SecurityFilterPosition() {
		_order = ordinal() * INTERVAL;
	}

	private SecurityFilterPosition(final int order) {
		_order = order;
	}

	public int getOrder() {
		return _order;
	}
}
