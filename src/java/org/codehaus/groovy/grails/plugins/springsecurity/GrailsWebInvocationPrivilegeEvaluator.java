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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.Principal;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletOutputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

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

	private static final FilterChain DUMMY_CHAIN = new FilterChain() {
		@Override
		public void doFilter(ServletRequest req, ServletResponse res) throws IOException, ServletException {
			throw new UnsupportedOperationException("GrailsWebInvocationPrivilegeEvaluator does not support filter chains");
		}
	};

	private static final HttpServletResponse DUMMY_RESPONSE = new DummyResponse();

	private AbstractSecurityInterceptor _interceptor;

	/**
	 * Constructor.
	 * @param interceptor the security interceptor
	 */
	public GrailsWebInvocationPrivilegeEvaluator(final AbstractSecurityInterceptor interceptor) {
		super(interceptor);
		_interceptor = interceptor;
	}

	@Override
	public boolean isAllowed(String contextPath, final String uri, final String method, final Authentication authentication) {
		Assert.notNull(uri, "uri parameter is required");

		if (contextPath == null) {
			contextPath = "/ctxpath";
		}

		FilterInvocation fi = createFilterInvocation(contextPath, uri, method);

		Collection<ConfigAttribute> attrs = _interceptor.obtainSecurityMetadataSource().getAttributes(fi);
		if (attrs == null) {
			return !_interceptor.isRejectPublicInvocations();
		}

		if (authentication == null) {
			return false;
		}

		try {
			_interceptor.getAccessDecisionManager().decide(authentication, fi, attrs);
			return true;
		}
		catch (AccessDeniedException unauthorized) {
			if (logger.isDebugEnabled()) {
				logger.debug(fi + " denied for " + authentication, unauthorized);
			}
			return false;
		}
	}

	protected FilterInvocation createFilterInvocation(final String contextPath, final String uri, final String method) {
		Assert.hasText(uri, "URI required");
		return new FilterInvocation(new DummyRequest(contextPath, method, contextPath + uri),
				DUMMY_RESPONSE, DUMMY_CHAIN);
	}
}

@SuppressWarnings("rawtypes")
class DummyRequest implements HttpServletRequest {

	private final String _contextPath;
	private final String _method;
	private final String _requestURI;
	private Map<String, Object> _attributes = new HashMap<String, Object>();

	DummyRequest(final String contextPath, final String method, final String requestURI) {
		_contextPath = contextPath;
		_method = method;
		_requestURI = requestURI;
	}

	@Override public String getContextPath() { return _contextPath; }
	@Override public String getMethod() { return _method; }
	@Override public String getRequestURI() { return _requestURI; }
	@Override public void setAttribute(String name, Object o) { _attributes.put(name, o); }
	@Override public Object getAttribute(String name) { return _attributes.get(name); }

	@Override public Map getParameterMap() { return Collections.emptyMap(); }
	@Override public String getCharacterEncoding() { return null; }
	@Override public Enumeration getParameterNames() { return Collections.enumeration(Collections.emptySet()); }
	@Override public String getServletPath() { return null; }
	@Override public String getPathInfo() { return null; }
	@Override public String getQueryString() { return null; }
	@Override public String getAuthType() { return null; }
	@Override public Cookie[] getCookies() { return null; }
	@Override public String getHeader(String name) { return null; }
	@Override public Enumeration getHeaderNames() { return Collections.enumeration(Collections.emptySet()); }
	@Override public Enumeration getHeaders(String name) { return Collections.enumeration(Collections.emptySet()); }
	@Override public String getPathTranslated() { return null; }
	@Override public String getRemoteUser() { return null; }
	@Override public String getRequestedSessionId() { return null; }
	@Override public Principal getUserPrincipal() { return null; }
	@Override public boolean isRequestedSessionIdFromCookie() { return false; }
	@Override public boolean isRequestedSessionIdFromURL() { return false; }
	@Override public boolean isRequestedSessionIdFromUrl() { return false; }
	@Override public boolean isRequestedSessionIdValid() { return false; }
	@Override public boolean isUserInRole(String role) { return false; }
	@Override public Enumeration getAttributeNames() { return Collections.enumeration(Collections.emptySet()); }
	@Override public String getContentType() { return null; }
	@Override public String getLocalAddr() { return null; }
	@Override public String getLocalName() { return null; }
	@Override public Locale getLocale() { return null; }
	@Override public Enumeration getLocales() { return Collections.enumeration(Collections.emptySet()); }
	@Override public String getParameter(String name) { return null; }
	@Override public String[] getParameterValues(String name) { return null; }
	@Override public String getProtocol() { return "http"; }
	@Override public String getRemoteAddr() { return null; }
	@Override public String getRemoteHost() { return null; }
	@Override public String getScheme() { return "http"; }
	@Override public String getServerName() { return "localhost"; }
	@Override public int getServerPort() { return 8080; }
	@Override public boolean isSecure() { return false; }
	@Override public void removeAttribute(String name) { /* do nothing */ }
	@Override public void setCharacterEncoding(String env) { /* do nothing */ }

	@Override public long getDateHeader(String name)                     { throw new UnsupportedOperationException(); }
	@Override public int getIntHeader(String name)                       { throw new UnsupportedOperationException(); }
	@Override public StringBuffer getRequestURL()                        { throw new UnsupportedOperationException(); }
	@Override public HttpSession getSession()                            { throw new UnsupportedOperationException(); }
	@Override public HttpSession getSession(boolean create)              { throw new UnsupportedOperationException(); }
	@Override public int getContentLength()                              { throw new UnsupportedOperationException(); }
	@Override public ServletInputStream getInputStream()                 { throw new UnsupportedOperationException(); }
	@Override public int getLocalPort()                                  { throw new UnsupportedOperationException(); }
	@Override public BufferedReader getReader()                          { throw new UnsupportedOperationException(); }
	@Override public String getRealPath(String path)                     { throw new UnsupportedOperationException(); }
	@Override public int getRemotePort()                                 { throw new UnsupportedOperationException(); }
	@Override public RequestDispatcher getRequestDispatcher(String path) { throw new UnsupportedOperationException(); }
}

class DummyResponse implements HttpServletResponse {
	@Override public void addCookie(Cookie cookie)              { throw new UnsupportedOperationException(); }
	@Override public void addDateHeader(String name, long date) { throw new UnsupportedOperationException(); }
	@Override public void addHeader(String name, String value)  { throw new UnsupportedOperationException(); }
	@Override public void addIntHeader(String name, int value)  { throw new UnsupportedOperationException(); }
	@Override public boolean containsHeader(String name)        { throw new UnsupportedOperationException(); }
	@Override public String encodeRedirectURL(String url)       { throw new UnsupportedOperationException(); }
	@Override public String encodeRedirectUrl(String url)       { throw new UnsupportedOperationException(); }
	@Override public String encodeURL(String url)               { throw new UnsupportedOperationException(); }
	@Override public String encodeUrl(String url)               { throw new UnsupportedOperationException(); }
	@Override public void sendError(int sc)                     { throw new UnsupportedOperationException(); }
	@Override public void sendError(int sc, String msg)         { throw new UnsupportedOperationException(); }
	@Override public void sendRedirect(String location)         { throw new UnsupportedOperationException(); }
	@Override public void setDateHeader(String name, long date) { throw new UnsupportedOperationException(); }
	@Override public void setHeader(String name, String value)  { throw new UnsupportedOperationException(); }
	@Override public void setIntHeader(String name, int value)  { throw new UnsupportedOperationException(); }
	@Override public void setStatus(int sc)                     { throw new UnsupportedOperationException(); }
	@Override public void setStatus(int sc, String sm)          { throw new UnsupportedOperationException(); }
	@Override public void flushBuffer()                         { throw new UnsupportedOperationException(); }
	@Override public int getBufferSize()                        { throw new UnsupportedOperationException(); }
	@Override public String getCharacterEncoding()              { throw new UnsupportedOperationException(); }
	@Override public String getContentType()                    { throw new UnsupportedOperationException(); }
	@Override public Locale getLocale()                         { throw new UnsupportedOperationException(); }
	@Override public ServletOutputStream getOutputStream()      { throw new UnsupportedOperationException(); }
	@Override public PrintWriter getWriter()                    { throw new UnsupportedOperationException(); }
	@Override public boolean isCommitted()                      { throw new UnsupportedOperationException(); }
	@Override public void reset()                               { throw new UnsupportedOperationException(); }
	@Override public void resetBuffer()                         { throw new UnsupportedOperationException(); }
	@Override public void setBufferSize(int size)               { throw new UnsupportedOperationException(); }
	@Override public void setCharacterEncoding(String charset)  { throw new UnsupportedOperationException(); }
	@Override public void setContentLength(int len)             { throw new UnsupportedOperationException(); }
	@Override public void setContentType(String type)           { throw new UnsupportedOperationException(); }
	@Override public void setLocale(Locale loc)                 { throw new UnsupportedOperationException(); }
}
