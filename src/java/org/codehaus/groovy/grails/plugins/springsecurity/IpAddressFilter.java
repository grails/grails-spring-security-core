/* Copyright 2006-2012 the original author or authors.
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

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.codehaus.groovy.grails.web.util.WebUtils;
import org.springframework.security.web.util.IpAddressMatcher;
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

	private final Logger _log = LoggerFactory.getLogger(getClass());

	private final AntPathMatcher _pathMatcher = new AntPathMatcher();

	private Map<String, List<String>> _restrictions;

	private static final String IPV4_LOOPBACK = "127.0.0.1";
	private static final String IPV6_LOOPBACK = "0:0:0:0:0:0:0:1";

	/**
	 * {@inheritDoc}
	 * @see javax.servlet.Filter#doFilter(javax.servlet.ServletRequest, javax.servlet.ServletResponse,
	 * 	javax.servlet.FilterChain)
	 */
	public void doFilter(final ServletRequest req, final ServletResponse res, final FilterChain chain)
				throws IOException, ServletException {

		HttpServletRequest request = (HttpServletRequest)req;
		HttpServletResponse response = (HttpServletResponse)res;

		if (!isAllowed(request)) {
			// send 404 to hide the existence of the resource
			response.sendError(HttpServletResponse.SC_NOT_FOUND);
			return;
		}

		chain.doFilter(request, response);
	}

	/**
	 * {@inheritDoc}
	 * @see org.springframework.web.filter.GenericFilterBean#initFilterBean()
	 */
	@Override
	protected void initFilterBean() {
		Assert.notNull(_restrictions, "ipRestrictions map is required");
	}

	/**
	 * Dependency injection for the ip/pattern restriction map. Keys are URL patterns and values
	 * are either single <code>String</code>s or <code>List</code>s of <code>String</code>s
	 * representing IP address patterns to allow for the specified URLs.
	 *
	 * @param restrictions the map
	 */
	public void setIpRestrictions(final Map<String, Object> restrictions) {
		_restrictions = ReflectionUtils.splitMap(restrictions);
	}

	private boolean isAllowed(final HttpServletRequest request) {
		String ip = request.getRemoteAddr();
		if (IPV4_LOOPBACK.equals(ip) || IPV6_LOOPBACK.equals(ip)) {
			// always allow localhost
			return true;
		}

		String uri = (String)request.getAttribute(WebUtils.FORWARD_REQUEST_URI_ATTRIBUTE);
		if (!StringUtils.hasLength(uri)) {
			uri = request.getRequestURI();
			if (!request.getContextPath().equals("/") && uri.startsWith(request.getContextPath())) {
				uri = uri.substring(request.getContextPath().length());
			}
		}

		Collection<Map.Entry<String, List<String>>> matching = findMatchingRules(uri);
		if (matching.isEmpty()) {
			return true;
		}

		for (Map.Entry<String, List<String>> entry : matching) {
			for (String ipPattern : entry.getValue()) {
				if (new IpAddressMatcher(ipPattern).matches(request)) {
					return true;
				}
			}
		}

		_log.warn("disallowed request " + uri + " from " + ip);
		return false;
	}

	private Collection<Map.Entry<String, List<String>>> findMatchingRules(String uri) {
		Collection<Map.Entry<String, List<String>>> matching =
			new ArrayList<Map.Entry<String, List<String>>>();
		for (Map.Entry<String, List<String>> entry : _restrictions.entrySet()) {
			String uriPattern = entry.getKey();
			if (_pathMatcher.match(uriPattern, uri)) {
				matching.add(entry);
			}
		}
		return matching;
	}
}
