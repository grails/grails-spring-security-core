/* Copyright 2006-2013 SpringSource.
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

import grails.plugin.springsecurity.web.access.expression.WebExpressionConfigAttribute

import org.codehaus.groovy.grails.commons.GrailsApplication
import org.codehaus.groovy.grails.plugins.web.api.ResponseMimeTypesApi
import org.codehaus.groovy.grails.web.mapping.UrlMapping
import org.codehaus.groovy.grails.web.mapping.UrlMappingInfo
import org.codehaus.groovy.grails.web.mapping.UrlMappingsHolder
import org.codehaus.groovy.grails.web.servlet.HttpHeaders
import org.codehaus.groovy.grails.web.servlet.mvc.GrailsWebRequest
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.expression.Expression
import org.springframework.expression.ParseException
import org.springframework.http.HttpMethod
import org.springframework.security.access.AccessDecisionVoter
import org.springframework.security.access.ConfigAttribute
import org.springframework.security.access.SecurityConfig
import org.springframework.security.access.expression.SecurityExpressionHandler

/**
 * Helper methods in Groovy.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class ReflectionUtils {

	private static final Logger log = LoggerFactory.getLogger(this)

	// set at startup
	static GrailsApplication application

	private ReflectionUtils() {
		// static only
	}

	static getConfigProperty(String name) {
		def value = SpringSecurityUtils.securityConfig
		for (String part in name.split('\\.')) {
			value = value."$part"
		}
		value
	}

	static void setConfigProperty(String name, value) {
		def config = SpringSecurityUtils.securityConfig
		def parts = name.split('\\.') as List
		name = parts.remove(parts.size() - 1)

		for (String part in parts) {
			config = config."$part"
		}

		config."$name" = value
	}

	static String getRoleAuthority(role) {
		lookupPropertyValue role, 'authority.nameField'
	}

	static String getRequestmapUrl(requestmap) {
		lookupPropertyValue requestmap, 'requestMap.urlField'
	}

	static String getRequestmapConfigAttribute(requestmap) {
		lookupPropertyValue requestmap, 'requestMap.configAttributeField'
	}

	static HttpMethod getRequestmapHttpMethod(requestmap) {
		lookupPropertyValue requestmap, 'requestMap.httpMethodField'
	}

	static List loadAllRequestmaps() {
		getRequestMapClass().list()
	}

	static boolean requestmapClassSupportsHttpMethod() {
		String httpMethodField = SpringSecurityUtils.securityConfig.requestMap.httpMethodField
		if (!httpMethodField) return false

		getRequestMapClass().metaClass.getProperties().find { MetaProperty p -> p.name == httpMethodField }
	}

	static Class getRequestMapClass() {
		String requestMapClassName = SpringSecurityUtils.securityConfig.requestMap.className
		if (!requestMapClassName) {
			throw new IllegalStateException(
					"Cannot load Requestmaps; 'requestMap.className' property is not specified")
		}
		def Requestmap = getApplication().getClassForName(requestMapClassName)
		if (!Requestmap) {
			throw new IllegalStateException(
					"Cannot load Requestmaps; 'requestMap.className' property '$requestMapClassName' is invalid")
		}
		Requestmap
	}

	static List asList(o) { o ? o as List : [] }

	static ConfigObject getSecurityConfig() {
		def grailsConfig = getApplication().config
		if (grailsConfig.grails.plugins.springsecurity) {
			log.error "Your security configuration settings use the old prefix 'grails.plugins.springsecurity' but must now use 'grails.plugin.springsecurity'"
		}
		grailsConfig.grails.plugin.springsecurity
	}

	static void setSecurityConfig(ConfigObject c) { getApplication().config.grails.plugin.springsecurity = c }

	static List<InterceptedUrl> splitMap(Map<String, Object> m, boolean expressions = true) {
		List<InterceptedUrl> split = []
		m.each { String key, value ->
			List tokens
			if (value instanceof List<?> || value.getClass().array) {
				tokens = value*.toString()
			}
			else { // String/GString
				tokens = [value.toString()]
			}
			split << new InterceptedUrl(key, null, ReflectionUtils.buildConfigAttributes(tokens, expressions))
		}
		split
	}

	// TODO doc List<Map> keys are pattern, access, httpMethod
	static List<InterceptedUrl> splitMap(List<Map<String, Object>> map) {
		List<InterceptedUrl> split = []

		for (Map<String, Object> row : map) {

			List tokens
			def value = map.access
			if (value instanceof List<?> || value.getClass().array) {
				tokens = value*.toString()
			}
			else { // String/GString
				tokens = [value.toString()]
			}

			def httpMethod = map.httpMethod
			if (httpMethod instanceof CharSequence) {
				httpMethod = HttpMethod.valueOf(httpMethod)
			}

			split << new InterceptedUrl(map.pattern, tokens, httpMethod)
		}

		split
	}

	static Collection<ConfigAttribute> buildConfigAttributes(Collection<String> tokens, boolean expressions = true) {
		Collection<ConfigAttribute> configAttributes = new LinkedHashSet<ConfigAttribute>()

		def ctx = getApplication().mainContext
		SecurityExpressionHandler expressionHandler = ctx.getBean('webExpressionHandler')
		AccessDecisionVoter roleVoter = ctx.getBean('roleVoter')
		AccessDecisionVoter authenticatedVoter = ctx.getBean('authenticatedVoter')

		for (String token : tokens) {
			ConfigAttribute config = new SecurityConfig(token)
			boolean supports = !expressions || token.startsWith('RUN_AS') || supports(config, roleVoter) || supports(config, authenticatedVoter)
			if (supports) {
				configAttributes << config
			}
			else {
				try {
					Expression expression = expressionHandler.expressionParser.parseExpression(token)
					configAttributes << new WebExpressionConfigAttribute(expression)
				}
				catch (ParseException e) {
					log.error "\nError parsing expression '$token': $e.message\n", e
					throw e
				}
			}
		}

		configAttributes
	}

	private static boolean supports(ConfigAttribute config, AccessDecisionVoter<?> voter) {
		voter.supports(config)
	}

	private static lookupPropertyValue(o, String name) {
		o."${getConfigProperty(name)}"
	}

	private static GrailsApplication getApplication() {
		if (!application) {
			application = org.codehaus.groovy.grails.commons.ApplicationHolder.application
		}
		application
	}

	// Grails 2.3+ only
	static UrlMappingInfo[] matchAllUrlMappings(UrlMappingsHolder urlMappingsHolder, String requestUrl, GrailsWebRequest grailsRequest,
	                                            ResponseMimeTypesApi responseMimeTypesApi) {
		String method = grailsRequest.currentRequest.method
		String version = grailsRequest.getHeader(HttpHeaders.ACCEPT_VERSION) ?: responseMimeTypesApi.getMimeTypeForRequest(grailsRequest).version
		urlMappingsHolder.matchAll requestUrl, method, version == null ? UrlMapping.ANY_VERSION : version
	}
}
