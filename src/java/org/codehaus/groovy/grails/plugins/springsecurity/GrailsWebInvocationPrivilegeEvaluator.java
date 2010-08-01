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

	public String getContextPath() { return _contextPath; }
	public String getMethod() { return _method; }
	public String getRequestURI() { return _requestURI; }
	public void setAttribute(String name, Object o) { _attributes.put(name, o); }
	public Object getAttribute(String name) { return _attributes.get(name); }

	public Map getParameterMap() { return Collections.emptyMap(); }
	public String getCharacterEncoding() { return null; }
	public Enumeration getParameterNames() { return Collections.enumeration(Collections.emptySet()); }
	public String getServletPath() { return null; }
	public String getPathInfo() { return null; }
	public String getQueryString() { return null; }
	public String getAuthType() { return null; }
	public Cookie[] getCookies() { return null; }
	public String getHeader(String name) { return null; }
	public Enumeration getHeaderNames() { return Collections.enumeration(Collections.emptySet()); }
	public Enumeration getHeaders(String name) { return Collections.enumeration(Collections.emptySet()); }
	public String getPathTranslated() { return null; }
	public String getRemoteUser() { return null; }
	public String getRequestedSessionId() { return null; }
	public Principal getUserPrincipal() { return null; }
	public boolean isRequestedSessionIdFromCookie() { return false; }
	public boolean isRequestedSessionIdFromURL() { return false; }
	public boolean isRequestedSessionIdFromUrl() { return false; }
	public boolean isRequestedSessionIdValid() { return false; }
	public boolean isUserInRole(String role) { return false; }
	public Enumeration getAttributeNames() { return Collections.enumeration(Collections.emptySet()); }
	public String getContentType() { return null; }
	public String getLocalAddr() { return null; }
	public String getLocalName() { return null; }
	public Locale getLocale() { return null; }
	public Enumeration getLocales() { return Collections.enumeration(Collections.emptySet()); }
	public String getParameter(String name) { return null; }
	public String[] getParameterValues(String name) { return null; }
	public String getProtocol() { return "http"; }
	public String getRemoteAddr() { return null; }
	public String getRemoteHost() { return null; }
	public String getScheme() { return "http"; }
	public String getServerName() { return "localhost"; }
	public int getServerPort() { return 8080; }
	public boolean isSecure() { return false; }
	public void removeAttribute(String name) { /* do nothing */ }
	public void setCharacterEncoding(String env) { /* do nothing */ }

	public long getDateHeader(String name)                     { throw new UnsupportedOperationException(); }
	public int getIntHeader(String name)                       { throw new UnsupportedOperationException(); }
	public StringBuffer getRequestURL()                        { throw new UnsupportedOperationException(); }
	public HttpSession getSession()                            { throw new UnsupportedOperationException(); }
	public HttpSession getSession(boolean create)              { throw new UnsupportedOperationException(); }
	public int getContentLength()                              { throw new UnsupportedOperationException(); }
	public ServletInputStream getInputStream()                 { throw new UnsupportedOperationException(); }
	public int getLocalPort()                                  { throw new UnsupportedOperationException(); }
	public BufferedReader getReader()                          { throw new UnsupportedOperationException(); }
	public String getRealPath(String path)                     { throw new UnsupportedOperationException(); }
	public int getRemotePort()                                 { throw new UnsupportedOperationException(); }
	public RequestDispatcher getRequestDispatcher(String path) { throw new UnsupportedOperationException(); }
}

class DummyResponse implements HttpServletResponse {
	public void addCookie(Cookie cookie)              { throw new UnsupportedOperationException(); }
	public void addDateHeader(String name, long date) { throw new UnsupportedOperationException(); }
	public void addHeader(String name, String value)  { throw new UnsupportedOperationException(); }
	public void addIntHeader(String name, int value)  { throw new UnsupportedOperationException(); }
	public boolean containsHeader(String name)        { throw new UnsupportedOperationException(); }
	public String encodeRedirectURL(String url)       { throw new UnsupportedOperationException(); }
	public String encodeRedirectUrl(String url)       { throw new UnsupportedOperationException(); }
	public String encodeURL(String url)               { throw new UnsupportedOperationException(); }
	public String encodeUrl(String url)               { throw new UnsupportedOperationException(); }
	public void sendError(int sc)                     { throw new UnsupportedOperationException(); }
	public void sendError(int sc, String msg)         { throw new UnsupportedOperationException(); }
	public void sendRedirect(String location)         { throw new UnsupportedOperationException(); }
	public void setDateHeader(String name, long date) { throw new UnsupportedOperationException(); }
	public void setHeader(String name, String value)  { throw new UnsupportedOperationException(); }
	public void setIntHeader(String name, int value)  { throw new UnsupportedOperationException(); }
	public void setStatus(int sc)                     { throw new UnsupportedOperationException(); }
	public void setStatus(int sc, String sm)          { throw new UnsupportedOperationException(); }
	public void flushBuffer()                         { throw new UnsupportedOperationException(); }
	public int getBufferSize()                        { throw new UnsupportedOperationException(); }
	public String getCharacterEncoding()              { throw new UnsupportedOperationException(); }
	public String getContentType()                    { throw new UnsupportedOperationException(); }
	public Locale getLocale()                         { throw new UnsupportedOperationException(); }
	public ServletOutputStream getOutputStream()      { throw new UnsupportedOperationException(); }
	public PrintWriter getWriter()                    { throw new UnsupportedOperationException(); }
	public boolean isCommitted()                      { throw new UnsupportedOperationException(); }
	public void reset()                               { throw new UnsupportedOperationException(); }
	public void resetBuffer()                         { throw new UnsupportedOperationException(); }
	public void setBufferSize(int size)               { throw new UnsupportedOperationException(); }
	public void setCharacterEncoding(String charset)  { throw new UnsupportedOperationException(); }
	public void setContentLength(int len)             { throw new UnsupportedOperationException(); }
	public void setContentType(String type)           { throw new UnsupportedOperationException(); }
	public void setLocale(Locale loc)                 { throw new UnsupportedOperationException(); }
}
