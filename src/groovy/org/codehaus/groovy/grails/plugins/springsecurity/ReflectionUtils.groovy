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
package org.codehaus.groovy.grails.plugins.springsecurity

import org.codehaus.groovy.grails.commons.ApplicationHolder as AH
import org.codehaus.groovy.grails.commons.ConfigurationHolder as CH

/**
 * Helper methods in Groovy.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class ReflectionUtils {

	private ReflectionUtils() {
		// static only
	}

	static getConfigProperty(String name) {
		SpringSecurityUtils.securityConfig."$name"
	}

	static getConfigProperty(String... names) {
		def current = SpringSecurityUtils.securityConfig
		for (String name in names) {
			current = current."$name"
		}
		current
	}

	static void setConfigProperty(String name, p) {
		SpringSecurityUtils.securityConfig."$name" = p
	}

	static String getRoleAuthority(role) {
		lookupPropertyValue role, 'authority', 'nameField'
	}

	static String getRequestmapUrl(requestmap) {
		lookupPropertyValue requestmap, 'requestMap', 'urlField'
	}

	static String getRequestmapConfigAttribute(requestmap) {
		lookupPropertyValue requestmap, 'requestMap', 'configAttributeField'
	}

	static List loadAllRequestmaps() {
		String requestMapClassName = SpringSecurityUtils.securityConfig.requestMap.className
		AH.application.getClassForName(requestMapClassName).list()
	}

	static List asList(authorities) {
		authorities ? authorities as List : []
	}

	static ConfigObject getSecurityConfig() { CH.config.grails.plugins.springsecurity }
	static void setSecurityConfig(ConfigObject c) { CH.config.grails.plugins.springsecurity = c }

	static Map<String, List<String>> splitMap(Map<String, Object> m) {
		Map<String, List<String>> split = [:]
		m.each { String key, value ->
			if (value instanceof List<?> || value.getClass().array) {
				split[key] = value*.toString()
			}
			else { // String/GString
				split[key] = [value.toString()]
			}
		}
		split
	}
	
	private static lookupPropertyValue(o, String... confPropertyNames) {
		String fieldName = getConfigProperty(confPropertyNames)
		o."$fieldName"
	}
}
