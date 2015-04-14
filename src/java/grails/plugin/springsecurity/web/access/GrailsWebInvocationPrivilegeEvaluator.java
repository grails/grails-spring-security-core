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
package grails.plugin.springsecurity.web.access;

import grails.util.GrailsUtil;

import java.io.IOException;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.intercept.AbstractSecurityInterceptor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.DefaultWebInvocationPrivilegeEvaluator;
import org.springframework.util.Assert;

/**
 * <code>createFilterInvocation()</code> is private in the base class so this is required to create
 * a mock request that works with Grails - more methods get called than are expected in the mock request
 * that the base class uses.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
public class GrailsWebInvocationPrivilegeEvaluator extends DefaultWebInvocationPrivilegeEvaluator {

	protected static final FilterChain DUMMY_CHAIN = new FilterChain() {
		public void doFilter(ServletRequest req, ServletResponse res) throws IOException, ServletException {
			throw new UnsupportedOperationException("GrailsWebInvocationPrivilegeEvaluator does not support filter chains");
		}
	};

	protected static final HttpServletResponse DUMMY_RESPONSE = DummyResponseCreator.createInstance();

	protected final Logger log = LoggerFactory.getLogger(getClass());

	protected AbstractSecurityInterceptor interceptor;

	/**
	 * Constructor.
	 * @param securityInterceptor the security interceptor
	 */
	public GrailsWebInvocationPrivilegeEvaluator(final AbstractSecurityInterceptor securityInterceptor) {
		super(securityInterceptor);
		interceptor = securityInterceptor;
	}

	@Override
	public boolean isAllowed(String contextPath, final String uri, final String method, final Authentication authentication) {
		Assert.notNull(uri, "uri parameter is required");

		if (contextPath == null) {
			contextPath = "/ctxpath";
		}

		FilterInvocation fi = createFilterInvocation(contextPath, uri, method);

		Collection<ConfigAttribute> attrs = interceptor.obtainSecurityMetadataSource().getAttributes(fi);
		if (attrs == null) {
			return !interceptor.isRejectPublicInvocations();
		}

		if (authentication == null) {
			return false;
		}

		try {
			interceptor.getAccessDecisionManager().decide(authentication, fi, attrs);
			return true;
		}
		catch (AccessDeniedException unauthorized) {
			if (log.isDebugEnabled()) {
				log.debug(fi + " denied for " + authentication, GrailsUtil.deepSanitize(unauthorized));
			}
			return false;
		}
	}

	protected FilterInvocation createFilterInvocation(final String contextPath, final String uri, final String method) {
		Assert.hasText(uri, "URI required");
		return new FilterInvocation(DummyRequestCreator.createInstance(contextPath, method, contextPath + uri),
				DUMMY_RESPONSE, DUMMY_CHAIN);
	}
}

class DummyRequestCreator {

	static HttpServletRequest createInstance(final String contextPath, final String httpMethod, final String requestURI) {
		final Map<String, Object> attributes = new HashMap<String, Object>();

		return (HttpServletRequest)Proxy.newProxyInstance(HttpServletRequest.class.getClassLoader(),
				new Class[] { HttpServletRequest.class }, new InvocationHandler() {
			public Object invoke(Object proxy, Method method, Object[] args) {

				String methodName = method.getName();

				if ("getContextPath".equals(methodName)) return contextPath;
				if ("getMethod".equals(methodName)) return httpMethod;
				if ("getRequestURI".equals(methodName)) return requestURI;
				if ("setAttribute".equals(methodName)) {
					attributes.put((String)args[0], args[1]);
					return null;
				}
				if ("getAttribute".equals(methodName)) {
					return attributes.get(args[0]);
				}

				if ("getProtocol".equals(methodName) || "getScheme".equals(methodName)) return "http";
				if ("getServerName".equals(methodName)) return "localhost";
				if ("getServerPort".equals(methodName)) return 8080;

				if (methodName.startsWith("is")) return false;

				if ("getParameterMap".equals(methodName)) return Collections.emptyMap();

				if ("getAttributeNames".equals(methodName) ||
						"getHeaderNames".equals(methodName) ||
						"getHeaders".equals(methodName) ||
						"getLocales".equals(methodName) ||
						"getParameterNames".equals(methodName)) {
					return Collections.enumeration(Collections.emptySet());
				}

				return null;
			}
		});
	}
}

class DummyResponseCreator {
	static HttpServletResponse createInstance() {
		return (HttpServletResponse)Proxy.newProxyInstance(HttpServletResponse.class.getClassLoader(),
				new Class[] { HttpServletResponse.class }, new InvocationHandler() {
			public Object invoke(Object proxy, Method method, Object[] args) {
				throw new UnsupportedOperationException();
			}
		});
	}
}
