/* Copyright 2006-2014 SpringSource.
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
package grails.plugin.springsecurity

import javax.servlet.FilterChain

import org.springframework.expression.Expression
import org.springframework.security.access.expression.ExpressionUtils
import org.springframework.security.web.FilterInvocation

/**
 * Security tags.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class SecurityTagLib {

	static namespace = 'sec'

	/** Dependency injection for springSecurityService. */
	def springSecurityService

	/** Dependency injection for webExpressionHandler. */
	def webExpressionHandler

	/** Dependency injection for webInvocationPrivilegeEvaluator. */
	def webInvocationPrivilegeEvaluator

	protected static final FilterChain DUMMY_CHAIN = [
		doFilter: { req, res -> throw new UnsupportedOperationException() }
	] as FilterChain

	protected Map<String, Expression> expressionCache = [:]

	/**
	 * Renders the body if all of the specified roles are granted to the user. Roles are
	 * specified in the 'roles' attribute which is a comma-delimited string.
	 *
	 * @attr roles REQUIRED the role name(s)
	 */
	def ifAllGranted = { attrs, body ->

		String roles = assertAttribute('roles', attrs, 'ifAllGranted')

		if (SpringSecurityUtils.ifAllGranted(roles)) {
			out << body()
		}
	}

	/**
	 * Renders the body if none of the specified roles are granted to the user. Roles are
	 * specified in the 'roles' attribute which is a comma-delimited string.
	 *
	 * @attr roles REQUIRED the role name(s)
	 */
	def ifNotGranted = { attrs, body ->

		String roles = assertAttribute('roles', attrs, 'ifNotGranted')

		if (SpringSecurityUtils.ifNotGranted(roles)) {
			out << body()
		}
	}

	/**
	 * Renders the body if any of the specified roles are granted to the user. Roles are
	 * specified in the 'roles' attribute which is a comma-delimited string.
	 *
	 * @attr roles REQUIRED the role name(s)
	 */
	def ifAnyGranted = { attrs, body ->

		String roles = assertAttribute('roles', attrs, 'ifAnyGranted')

		if (SpringSecurityUtils.ifAnyGranted(roles)) {
			out << body()
		}
	}

	/**
	 * Renders a property (specified by the 'field' attribute) from the principal.
	 *
	 * @attr field REQUIRED the field name
	 */
	def loggedInUserInfo = { attrs, body ->

		// TODO support 'var' and 'scope' and set the result instead of writing it

		String field = assertAttribute('field', attrs, 'loggedInUserInfo')

		def source
		if (springSecurityService.isLoggedIn()) {
			source = determineSource()
			for (pathElement in field.split('\\.')) {
				source = source."$pathElement"
				if (source == null) {
					break
				}
			}
		}

		if (source) {
			out << source.encodeAsHTML()
		}
		else {
			out << body()
		}
	}

	/**
	 * Renders the user's username if logged in.
	 */
	def username = { attrs ->
		if (springSecurityService.isLoggedIn()) {
			out << springSecurityService.authentication.name.encodeAsHTML()
		}
	}

	/**
	 * Renders the body if the user is authenticated.
	 */
	def ifLoggedIn = { attrs, body ->
		if (springSecurityService.isLoggedIn()) {
			out << body()
		}
	}

	/**
	 * Renders the body if the user is not authenticated.
	 */
	def ifNotLoggedIn = { attrs, body ->
		if (!springSecurityService.isLoggedIn()) {
			out << body()
		}
	}

	/**
	 * Renders the body if the user is authenticated as another user via run-as.
	 */
	def ifSwitched = { attrs, body ->
		if (SpringSecurityUtils.isSwitched()) {
			out << body()
		}
	}

	/**
	 * Renders the body if the user is not authenticated as another user via run-as.
	 */
	def ifNotSwitched = { attrs, body ->
		if (!SpringSecurityUtils.isSwitched()) {
			out << body()
		}
	}

	/**
	 * Renders the username of the 'real' authentication when authenticated as another user via run-as.
	 */
	def switchedUserOriginalUsername = { attrs ->
		if (SpringSecurityUtils.isSwitched()) {
			out << SpringSecurityUtils.switchedUserOriginalUsername.encodeAsHTML()
		}
	}

	/**
	 * Renders the body if the specified expression (a String; the 'expression' attribute)
	 * evaluates to <code>true</code> or if the specified URL is allowed.
	 *
	 * @attr expression the expression to evaluate
	 * @attr url the URL to check
	 * @attr method the method of the URL, defaults to 'GET'
	 */
	def access = { attrs, body ->
		if (hasAccess(attrs, 'access')) {
			out << body()
		}
	}

    /**
     * Provides a wrapper around the standard Grails link tag <code>g:link</code>.
     * Renders the link if the user has access to the specified URL.
     */
    def link = { attrs, body ->
        // retain original attributes for later, since hasAccess() removes ones necessary to create a link
        def origAttrsMinusExpression = new HashMap(attrs)
        origAttrsMinusExpression.remove('expression')
        if (hasAccess(attrs, 'link')) {
            out << g.link(origAttrsMinusExpression, body)
        }
    }

	/**
	 * Renders the body if the specified expression (a String; the 'expression' attribute)
	 * evaluates to <code>false</code> or if the specified URL is not allowed.
	 *
	 * @attr expression the expression to evaluate
	 * @attr url the URL to check
	 * @attr method the method of the URL, defaults to 'GET'
	 */
	def noAccess = { attrs, body ->
		if (!hasAccess(attrs, 'noAccess')) {
			out << body()
		}
	}

	protected boolean hasAccess(attrs, String tagName) {

		if (!springSecurityService.isLoggedIn()) {
			return false
		}
		def auth = springSecurityService.authentication
		String expressionText = attrs.remove('expression')
		if (expressionText) {
			Expression expression = findOrCreateExpression(expressionText)
			FilterInvocation fi = new FilterInvocation(request, response, DUMMY_CHAIN)
			def ctx = webExpressionHandler.createEvaluationContext(auth, fi)
			return ExpressionUtils.evaluateAsBoolean(expression, ctx)
		}

		String url = attrs.remove('url')
		if (!url) {
			String controller = attrs.remove('controller')
			String mapping = attrs.remove('mapping')
			if (!controller && !mapping) {
				throwTagError "Tag [$tagName] requires an expression, a URL, or controller/action/mapping attributes to create a URL"
			}
			if (mapping) {
				url = g.createLink(mapping: mapping).toString()
			}
			else {
				String action = attrs.remove('action')
				url = g.createLink(controller: controller, action: action, base: '/').toString()
			}
		}

		String method = attrs.remove('method') ?: 'GET'

		return webInvocationPrivilegeEvaluator.isAllowed(request.contextPath, url, method, auth)
	}

	protected assertAttribute(String name, attrs, String tag) {
		if (!attrs.containsKey(name)) {
			throwTagError "Tag [$tag] is missing required attribute [$name]"
		}
		attrs.remove name
	}

	protected determineSource() {
		def principal = springSecurityService.principal

		// check to see if it's a GrailsUser/GrailsUserImpl/subclass,
		// or otherwise has a 'domainClass' property
		if (principal.metaClass.respondsTo(principal, 'getDomainClass')) {
			return principal.domainClass
		}

		principal
	}

	protected synchronized Expression findOrCreateExpression(String text) {
		Expression expression = expressionCache.get(text)
		if (!expression) {
			expression = webExpressionHandler.expressionParser.parseExpression(text)
			expressionCache[text] = expression
		}
		return expression
	}
}
