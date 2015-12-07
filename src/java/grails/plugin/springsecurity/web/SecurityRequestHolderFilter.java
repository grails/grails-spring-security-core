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

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.PortMapper;
import org.springframework.security.web.PortResolver;
import org.springframework.web.filter.GenericFilterBean;

/**
* Stores the request and response in the {@link SecurityRequestHolder}. Also wraps the request in a
* wrapper that is aware of the X-Forwarded-Proto header and returns the correct value from isSecure(),
* getScheme(), and getServerPort() if the header is present.
*
* @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
*/
public class SecurityRequestHolderFilter extends GenericFilterBean {

	protected final Logger log = LoggerFactory.getLogger(getClass());

	protected boolean useHeaderCheckChannelSecurity;
	protected String secureHeaderName;
	protected String secureHeaderValue;
	protected String insecureHeaderName;
	protected String insecureHeaderValue;
	protected PortMapper portMapper;
	protected PortResolver portResolver;

	public void doFilter(ServletRequest req, ServletResponse response, FilterChain chain) throws IOException, ServletException {

		HttpServletRequest request = wrapRequest((HttpServletRequest)req);

		SecurityRequestHolder.set(request, (HttpServletResponse)response);

		try {
			chain.doFilter(request, response);
		}
		finally {
			SecurityRequestHolder.reset();
		}
	}

	/**
	 * If using header check channel security, look for the specified header (typically 'X-Forwarded-Proto')
	 * and if found, return a request wrapper that returns the correct values for isSecure(), getScheme(),
	 * and getServerPort(). Note that the values are switched intentionally since they're configured for
	 * channel security.
	 *
	 * @param request the original request
	 * @return the original request or a wrapper for it
	 */
	protected HttpServletRequest wrapRequest(final HttpServletRequest request) {
		if (!useHeaderCheckChannelSecurity) {
			return request;
		}

		if (insecureHeaderValue.equals(request.getHeader(secureHeaderName)) && "http".equals(request.getScheme())) {
			return new HttpServletRequestWrapper(request) {
				@Override public boolean isSecure() { return true; }
				@Override public String getScheme() { return "https"; }
				@Override public int getServerPort() {
					int serverPort = portResolver.getServerPort(request);
					Integer httpsPort = portMapper.lookupHttpsPort(serverPort);
					if (httpsPort == null) {
						log.warn("No port mapping found for HTTP port {}", serverPort);
						httpsPort = serverPort;
					}
					return httpsPort;
				}
			};
		}

		if (secureHeaderValue.equals(request.getHeader(insecureHeaderName)) && "https".equals(request.getScheme())) {
			return new HttpServletRequestWrapper(request) {
				@Override public boolean isSecure() { return false; }
				@Override public String getScheme() { return "http"; }
				@Override public int getServerPort() {
					int serverPort = portResolver.getServerPort(request);
					Integer httpPort = portMapper.lookupHttpPort(serverPort);
					if (httpPort == null) {
						log.warn("No port mapping found for HTTPS port {}", serverPort);
						httpPort = serverPort;
					}
					return httpPort;
				}
			};
		}

		return request;
	}

	// dependency injection methods

	public void setUseHeaderCheckChannelSecurity(boolean use) {
		useHeaderCheckChannelSecurity = use;
	}

	public void setSecureHeaderName(String name) {
		secureHeaderName = name;
	}

	public void setSecureHeaderValue(String value) {
		secureHeaderValue = value;
	}

	public void setInsecureHeaderName(String name) {
		insecureHeaderName = name;
	}

	public void setInsecureHeaderValue(String value) {
		insecureHeaderValue = value;
	}

	public void setPortMapper(PortMapper mapper) {
		portMapper = mapper;
	}

	public void setPortResolver(PortResolver resolver) {
		portResolver = resolver;
	}
}
