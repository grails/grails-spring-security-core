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
package grails.plugin.springsecurity;

/**
 * Stores the default order numbers of all Spring Security filters for use in configuration.
 * <p/>
 * Equivalent to <code>org.springframework.security.config.http.SecurityFilters</code> which
 * unfortunately is package-default.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
public enum SecurityFilterPosition {
	/** First */
	FIRST(Integer.MIN_VALUE),
	/** HTTP/HTTPS channel filter */
	CHANNEL_FILTER,
	/** Concurrent Sessions */
	CONCURRENT_SESSION_FILTER,
	/** Populates the SecurityContextHolder */
	SECURITY_CONTEXT_FILTER,
	/** Logout */
	LOGOUT_FILTER,
	/** x509 certs */
	X509_FILTER,
	/** Pre-auth */
	PRE_AUTH_FILTER,
	/** CAS */
	CAS_FILTER,
	/** UsernamePasswordAuthenticationFilter */
	FORM_LOGIN_FILTER,
	/** OpenID */
	OPENID_FILTER,
	/** Not used, generates a dynamic login form */
	LOGIN_PAGE_FILTER,
	/** Digest auth */
	DIGEST_AUTH_FILTER,
	/** Basic Auth */
	BASIC_AUTH_FILTER,
	/** saved request filter */
	REQUEST_CACHE_FILTER,
	/** SecurityContextHolderAwareRequestFilter */
	SERVLET_API_SUPPORT_FILTER,
	/** Remember-me cookie */
	REMEMBER_ME_FILTER,
	/** Anonymous auth */
	ANONYMOUS_FILTER,
	/** SessionManagementFilter */
	SESSION_MANAGEMENT_FILTER,
	/** ExceptionTranslationFilter */
	EXCEPTION_TRANSLATION_FILTER,
	/** FilterSecurityInterceptor */
	FILTER_SECURITY_INTERCEPTOR,
	/** Switch user */
	SWITCH_USER_FILTER,
	/** Last */
	LAST(Integer.MAX_VALUE);

	private static final int INTERVAL = 100;

	private final int order;

	private SecurityFilterPosition() {
		order = ordinal() * INTERVAL;
	}

	private SecurityFilterPosition(final int filterOrder) {
		order = filterOrder;
	}

	/**
	 * The position in the chain.
	 * @return the order
	 */
	public int getOrder() {
		return order;
	}
}
