/* Copyright 2015 the original author or authors.
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

import java.io.IOException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.StringUtils;

/**
 * Based on org.springframework.security.web.DefaultRedirectStrategy.
 *
 * @author Burt Beckwith
 */
public class GrailsRedirectStrategy implements RedirectStrategy {

	private final Logger log = LoggerFactory.getLogger(getClass());

	protected boolean contextRelative;
	protected String insecureHeaderName;
	protected String insecureHeaderValue;
	protected String secureHeaderName;
	protected String secureHeaderValue;

	/**
	 * Redirects the response to the supplied URL.
	 * <p>
	 * If <tt>contextRelative</tt> is set, the redirect value will be the value after the request context path. Note
	 * that this will result in the loss of protocol information (HTTP or HTTPS), so will cause problems if a
	 * redirect is being performed to change to HTTPS, for example.
	 */
	public void sendRedirect(HttpServletRequest request, HttpServletResponse response, String url) throws IOException {
		String redirectUrl = calculateRedirectUrl(request.getContextPath(), url);
		redirectUrl = response.encodeRedirectURL(redirectUrl);

		log.debug("Redirecting to '{}'", redirectUrl);

		response.sendRedirect(redirectUrl);
	}

	protected String calculateRedirectUrl(String contextPath, String url) {
		if (!UrlUtils.isAbsoluteUrl(url)) {
			return contextRelative ? url : contextPath + url;
		}

		// Full URL, including http(s)://

		if (!contextRelative) {
			return url;
		}

		// Calculate the relative URL from the fully qualified URL, minus the last
		// occurrence of the scheme and base context.
		url = url.substring(url.lastIndexOf("://") + 3); // strip off scheme
		url = url.substring(url.indexOf(contextPath) + contextPath.length());

		if (url.length() > 1 && url.charAt(0) == '/') {
			url = url.substring(1);
		}

		return url;
	}

	/**
	 * If <tt>true</tt>, causes any redirection URLs to be calculated minus the protocol
	 * and context path (defaults to <tt>false</tt>).
	 */
	public void setContextRelative(boolean useRelativeContext) {
		contextRelative = useRelativeContext;
	}

	/**
	 * Set the name of the secure header to check.
	 * @param name the name
	 */
	public void setSecureHeaderName(String name) {
		secureHeaderName = name;
	}

	/**
	 * Set the secure header value to use for redirects.
	 * @param value the value
	 */
	public void setSecureHeaderValue(String value) {
		secureHeaderValue = value;
	}

	/**
	 * Set the name of the insecure header to check.
	 * @param name the name
	 */
	public void setInsecureHeaderName(String name) {
		insecureHeaderName = name;
	}

	/**
	 * Set the insecure header value to use for redirects.
	 * @param value the value
	 */
	public void setInsecureHeaderValue(String value) {
		insecureHeaderValue = value;
	}
}
