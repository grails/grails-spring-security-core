/* Copyright 2006-2013 SpringSource.
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
package grails.plugin.springsecurity.web;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Uses a {@link ThreadLocal} to store the current request and response.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
public final class SecurityRequestHolder {

	private static final ThreadLocal<HttpServletRequest> REQUEST_HOLDER = new ThreadLocal<HttpServletRequest>();
	private static final ThreadLocal<HttpServletResponse> RESPONSE_HOLDER = new ThreadLocal<HttpServletResponse>();

	private SecurityRequestHolder() {
		// static only
	}

	/**
	 * Clear the saved request.
	 */
	public static void reset() {
		REQUEST_HOLDER.set(null);
		RESPONSE_HOLDER.set(null);
	}

	/**
	 * Set the current request and response.
	 * @param request the request
	 * @param response the response
	 */
	public static void set(final HttpServletRequest request, final HttpServletResponse response) {
		REQUEST_HOLDER.set(request);
		RESPONSE_HOLDER.set(response);
	}

	/**
	 * Get the current request.
	 * @return the request
	 */
	public static HttpServletRequest getRequest() {
		return REQUEST_HOLDER.get();
	}

	/**
	 * Get the current response.
	 * @return the response
	 */
	public static HttpServletResponse getResponse() {
		return RESPONSE_HOLDER.get();
	}
}
