/* Copyright 2013-2015 the original author or authors.
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

import grails.util.GrailsUtil;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.List;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.web.filter.GenericFilterBean;

/**
 * Based on the package-scope org.springframework.security.config.debug.DebugFilter.
 *
 * @author Luke Taylor
 * @author Rob Winch
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
public class DebugFilter extends GenericFilterBean {

	protected static final String ALREADY_FILTERED_ATTR_NAME = DebugFilter.class.getName() + ".FILTERED";

	protected final FilterChainProxy filterChainProxy;
	protected final Logger log = LoggerFactory.getLogger(getClass());

	public DebugFilter(FilterChainProxy fcp) {
		filterChainProxy = fcp;
	}

	public void doFilter(ServletRequest req, ServletResponse res, FilterChain filterChain) throws ServletException, IOException {

		HttpServletRequest request = (HttpServletRequest)req;
		HttpServletResponse response = (HttpServletResponse)res;

		List<Filter> filters = getFilters(request);
		log(false, "Request received for '{}':\n\n{}\n\nservletPath:{}\npathInfo:{}\n\n{}",
				UrlUtils.buildRequestUrl(request), request, request.getServletPath(), request.getPathInfo(), formatFilters(filters));

		if (request.getAttribute(ALREADY_FILTERED_ATTR_NAME) == null) {
			invokeWithWrappedRequest(request, response, filterChain);
		}
		else {
			filterChainProxy.doFilter(request, response, filterChain);
		}
	}

	protected void invokeWithWrappedRequest(HttpServletRequest request, HttpServletResponse response,
			FilterChain filterChain) throws IOException, ServletException {

		request.setAttribute(ALREADY_FILTERED_ATTR_NAME, true);

		request = new HttpServletRequestWrapper(request) {

			@Override
			public HttpSession getSession() {
				boolean sessionExists = super.getSession(false) != null;
				HttpSession session = super.getSession();

				if (!sessionExists) {
					log(true, "New HTTP session created: {}", session.getId());
				}

				return session;
			}

			@Override
			public HttpSession getSession(boolean create) {
				return create ? getSession() : super.getSession(false);
			}
		};

		try {
			filterChainProxy.doFilter(request, response, filterChain);
		}
		finally {
			request.removeAttribute(ALREADY_FILTERED_ATTR_NAME);
		}
	}

	protected String formatFilters(List<Filter> filters) {
		StringBuilder sb = new StringBuilder("Security filter chain: ");
		if (filters == null) {
			sb.append("no match");
		}
		else if (filters.isEmpty()) {
			sb.append("[] empty (bypassed by security='none') ");
		}
		else {
			sb.append("[\n");
			for (Filter f : filters) {
				sb.append("  ").append(f.getClass().getSimpleName()).append("\n");
			}
			sb.append("]");
		}

		return sb.toString();
	}

	protected List<Filter> getFilters(HttpServletRequest request) {
		for (SecurityFilterChain chain : filterChainProxy.getFilterChains()) {
			if (chain.matches(request)) {
				return chain.getFilters();
			}
		}

		return null;
	}

	protected void log(boolean dumpStack, String message, Object... args) {
		StringBuilder output = new StringBuilder(256);
		output.append("\n\n************************************************************\n\n");
		output.append(message).append("\n");

		if (dumpStack) {
			StringWriter os = new StringWriter();
			GrailsUtil.deepSanitize(new Exception()).printStackTrace(new PrintWriter(os));
			StringBuffer buffer = os.getBuffer();
			// Remove the exception in case it scares people.
			int start = buffer.indexOf("java.lang.Exception");
			buffer.replace(start, start + 19, "");
			output.append("\nCall stack: \n").append(os);
		}

		output.append("\n\n************************************************************\n\n");
		log.info(output.toString(), args);
	}

	public FilterChainProxy getFilterChainProxy() {
		return filterChainProxy;
	}
}
