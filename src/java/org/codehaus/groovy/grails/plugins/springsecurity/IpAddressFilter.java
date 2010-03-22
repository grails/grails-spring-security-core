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

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.GenericFilterBean;

/**
 * Blocks access to protected resources based on IP address. Sends 404 rather than
 * reporting error to hide visibility of the resources.
 * <br/>
 * Supports either Ant-style patterns (e.g. 10.**) or masked patterns
 * (e.g. 192.168.1.0/24 or 202.24.0.0/14).
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
public class IpAddressFilter extends GenericFilterBean {

	private final Logger _log = Logger.getLogger(getClass());

	private final AntPathMatcher _pathMatcher = new AntPathMatcher();

	private Map<String, List<String>> _restrictions;

	/**
	 * {@inheritDoc}
	 * @see javax.servlet.Filter#doFilter(javax.servlet.ServletRequest, javax.servlet.ServletResponse,
	 * 	javax.servlet.FilterChain)
	 */
	public void doFilter(final ServletRequest req, final ServletResponse res, final FilterChain chain)
				throws IOException, ServletException {

		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;

		if (!isAllowed(request.getRemoteAddr(), request.getRequestURI())) {
			response.sendError(HttpServletResponse.SC_NOT_FOUND); // 404
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
	 * Dependency injection for the ip/pattern restriction map. Keys are URL patterns and values are either
	 * single <code>String</code>s or <code>List</code>s of <code>String</code>s representing IP address patterns
	 * to allow for the specified URLs.
	 *
	 * @param restrictions  the map
	 */
	public void setIpRestrictions(final Map<String, Object> restrictions) {
		_restrictions = ReflectionUtils.splitMap(restrictions);
	}

	private boolean isAllowed(final String ip, final String requestURI) {

		if ("127.0.0.1".equals(ip)) {
			return true;
		}

		String reason = null;

		for (Map.Entry<String, List<String>> entry : _restrictions.entrySet()) {
			String uriPattern = entry.getKey();
			if (!_pathMatcher.match(uriPattern, requestURI)) {
				continue;
			}

			for (String ipPattern : entry.getValue()) {
				if (ipPattern.contains("/")) {
					try {
						if (!matchesUsingMask(ipPattern, ip)) {
							reason = ipPattern;
						}
					}
					catch (UnknownHostException e) {
						reason = e.getMessage();
					}
				}
				else if (!_pathMatcher.match(ipPattern, ip)) {
					reason = ipPattern;
				}

				if (reason != null) {
					break;
				}
			}

			break;
		}

		if (reason != null) {
			_log.error("disallowed request " + requestURI + " from " + ip + ": " + reason);
			return false;
		}

		return true;
	}

	private boolean matchesUsingMask(final String ipPattern, final String ip) throws UnknownHostException {

		String[] addressAndMask = StringUtils.split(ipPattern, "/");

		InetAddress requiredAddress = parseAddress(addressAndMask[0]);
		InetAddress remoteAddress = parseAddress(ip);
		Assert.isTrue(requiredAddress.getClass().equals(remoteAddress.getClass()),
				"IP Address in expression must be the same type as version returned by request");

		int maskBits = Integer.parseInt(addressAndMask[1]);
		if (maskBits == 0) {
			return remoteAddress.equals(requiredAddress);
		}

		int oddBits = maskBits % 8;
		byte[] mask = new byte[maskBits / 8 + (oddBits == 0 ? 0 : 1)];

		Arrays.fill(mask, 0, oddBits == 0 ? mask.length : mask.length - 1, (byte)0xFF);

		if (oddBits != 0) {
			int finalByte = (1 << oddBits) - 1;
			finalByte <<= 8 - oddBits;
			mask[mask.length - 1] = (byte) finalByte;
		}

		byte[] remoteAddressBytes = remoteAddress.getAddress();
		byte[] requiredAddressBytes = requiredAddress.getAddress();
		for (int i = 0; i < mask.length; i++) {
			if ((remoteAddressBytes[i] & mask[i]) != (requiredAddressBytes[i] & mask[i])) {
				return false;
			}
		}

		return true;
	}

	private InetAddress parseAddress(final String address) throws UnknownHostException {
		try {
			return InetAddress.getByName(address);
		}
		catch (UnknownHostException e) {
			_log.error("unable to parse " + address);
			throw e;
		}
	}
}
