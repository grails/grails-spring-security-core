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
import org.springframework.security.web.PortResolver;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.util.UrlUtils;

/**
* Builds absolute urls when using header check channel security to prevent the
* container from generating urls with an incorrect scheme.
*
* @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
*/
public class GrailsRedirectStrategy implements RedirectStrategy {

	protected final Logger log = LoggerFactory.getLogger(getClass());

	protected PortResolver portResolver;
	protected boolean useHeaderCheckChannelSecurity;

	public void sendRedirect(HttpServletRequest request, HttpServletResponse response, String url) throws IOException {
		String redirectUrl = calculateRedirectUrl(request, url);
		redirectUrl = response.encodeRedirectURL(redirectUrl);

		log.debug("Redirecting to '{}'", redirectUrl);

		response.sendRedirect(redirectUrl);
	}

	protected String calculateRedirectUrl(HttpServletRequest request, String url) {
		if (UrlUtils.isAbsoluteUrl(url)) {
			return url;
		}

		url = request.getContextPath() + url;

		if (!useHeaderCheckChannelSecurity) {
			return url;
		}

		return UrlUtils.buildFullRequestUrl(request.getScheme(), request.getServerName(),
				portResolver.getServerPort(request), url, null);
	}

	/**
	 * Dependency injection for useHeaderCheckChannelSecurity.
	 * @param use
	 */
	public void setUseHeaderCheckChannelSecurity(boolean use) {
		useHeaderCheckChannelSecurity = use;
	}

	/**
	 * Dependency injection for the port resolver.
	 * @param portResolver the port resolver
	 */
	public void setPortResolver(PortResolver portResolver) {
		this.portResolver = portResolver;
	}
}
