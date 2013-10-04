/* Copyright 2013 SpringSource.
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
package grails.plugin.springsecurity.web.authentication;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.web.util.RequestMatcher;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;

/**
 * Based on the class of the same name which is a private static inner class in
 * org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter.
 *
 * @author Ben Alex
 * @author Luke Taylor
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
public class FilterProcessUrlRequestMatcher implements RequestMatcher {

	private final String filterProcessesUrl;

	public FilterProcessUrlRequestMatcher(String filterProcessesUrl) {
		Assert.hasLength(filterProcessesUrl, "filterProcessesUrl must be specified");
		Assert.isTrue(UrlUtils.isValidRedirectUrl(filterProcessesUrl), filterProcessesUrl + " isn't a valid redirect URL");
		this.filterProcessesUrl = filterProcessesUrl;
	}

	public boolean matches(final HttpServletRequest request) {
		String uri = request.getRequestURI();
		int pathParamIndex = uri.indexOf(';');

		if (pathParamIndex > 0) {
			// strip everything after the first semi-colon
			uri = uri.substring(0, pathParamIndex);
		}

		if ("".equals(request.getContextPath())) {
			return uri.endsWith(filterProcessesUrl);
		}

		return uri.endsWith(request.getContextPath() + filterProcessesUrl);
	}

	protected String getFilterProcessesUrl() {
		return filterProcessesUrl;
	}
}
