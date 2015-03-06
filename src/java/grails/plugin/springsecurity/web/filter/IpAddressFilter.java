/* Copyright 2006-2015 SpringSource.
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
package grails.plugin.springsecurity.web.filter;

import grails.plugin.springsecurity.InterceptedUrl;
import grails.plugin.springsecurity.ReflectionUtils;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.codehaus.groovy.grails.web.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.util.matcher.IpAddressMatcher;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

/**
 * Blocks access to protected resources based on IP address. Sends 404 rather than
 * reporting error to hide visibility of the resources.
 * <br/>
 * Supports either single IP addresses or CIDR masked patterns
 * (e.g. 192.168.1.0/24, 202.24.0.0/14, 10.0.0.0/8, etc.).
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
public class IpAddressFilter extends GenericFilterBean {

	protected static final String IPV4_LOOPBACK = "127.0.0.1";
	protected static final String IPV6_LOOPBACK = "0:0:0:0:0:0:0:1";

	protected final Logger log = LoggerFactory.getLogger(getClass());

	protected final AntPathMatcher pathMatcher = new AntPathMatcher();

	protected List<InterceptedUrl> restrictions;
	protected boolean allowLocalhost = true;

	public void doFilter(final ServletRequest req, final ServletResponse res, final FilterChain chain)
				throws IOException, ServletException {

		HttpServletRequest request = (HttpServletRequest)req;
		HttpServletResponse response = (HttpServletResponse)res;

		if (!isAllowed(request)) {
			deny(request, response);
			return;
		}

		chain.doFilter(request, response);
	}

	protected void deny(final HttpServletRequest req, final HttpServletResponse res) throws IOException {
		// send 404 to hide the existence of the resource
		res.sendError(HttpServletResponse.SC_NOT_FOUND);
	}

	@Override
	protected void initFilterBean() {
		Assert.notNull(restrictions, "ipRestrictions map is required");
	}

	/**
	 * Dependency injection for the ip/pattern restriction map. Keys are URL patterns and values
	 * are either single <code>String</code>s or <code>List</code>s of <code>String</code>s
	 * representing IP address patterns to allow for the specified URLs.
	 *
	 * @param ipRestrictions the map
	 */
	public void setIpRestrictions(final Map<String, Object> ipRestrictions) {
		restrictions = ReflectionUtils.splitMap(ipRestrictions, false);
	}

	/**
	 * Dependency injection for whether to allow localhost calls (useful for testing).
	 * TODO document
	 *
	 * @param allow if <code>true</code> allow localhost access
	 */
	public void setAllowLocalhost(boolean allow) {
		allowLocalhost = allow;
	}

	protected boolean isAllowed(final HttpServletRequest request) {
		String ip = request.getRemoteAddr();
		if (allowLocalhost && (IPV4_LOOPBACK.equals(ip) || IPV6_LOOPBACK.equals(ip))) {
			return true;
		}

		String uri = (String)request.getAttribute(WebUtils.FORWARD_REQUEST_URI_ATTRIBUTE);
		if (!StringUtils.hasLength(uri)) {
			uri = request.getRequestURI();
			if (!request.getContextPath().equals("/") && uri.startsWith(request.getContextPath())) {
				uri = uri.substring(request.getContextPath().length());
			}
		}

		List<InterceptedUrl> matching = findMatchingRules(uri);
		if (matching.isEmpty()) {
			return true;
		}

		for (InterceptedUrl iu : matching) {
			for (ConfigAttribute ipPattern : iu.getConfigAttributes()) {
				if (new IpAddressMatcher(ipPattern.getAttribute()).matches(request)) {
					return true;
				}
			}
		}

		log.warn("disallowed request {} from {}", new Object[] { uri, ip });
		return false;
	}

	protected List<InterceptedUrl> findMatchingRules(String uri) {
		List<InterceptedUrl> matching = new ArrayList<InterceptedUrl>();
		for (InterceptedUrl iu : restrictions) {
			if (pathMatcher.match(iu.getPattern(), uri)) {
				matching.add(iu);
			}
		}
		return matching;
	}
}
