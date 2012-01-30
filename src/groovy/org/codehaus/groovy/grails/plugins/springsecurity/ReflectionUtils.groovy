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
package org.codehaus.groovy.grails.plugins.springsecurity

import org.codehaus.groovy.grails.commons.ApplicationHolder
import org.codehaus.groovy.grails.commons.GrailsApplication

/**
 * Helper methods in Groovy.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class ReflectionUtils {

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

	static List loadAllRequestmaps() {
		String requestMapClassName = SpringSecurityUtils.securityConfig.requestMap.className
		def Requestmap = getApplication().getClassForName(requestMapClassName)
		if (!Requestmap) {
			throw new IllegalStateException(
					'Cannot load Requestmaps, "requestMap.className" property is not set')
		}
		Requestmap.list()
	}

	static List asList(o) { o ? o as List : [] }

	static ConfigObject getSecurityConfig() { getApplication().config.grails.plugins.springsecurity }
	static void setSecurityConfig(ConfigObject c) { getApplication().config.grails.plugins.springsecurity = c }

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

	private static lookupPropertyValue(o, String name) {
		o."${getConfigProperty(name)}"
	}

	private static GrailsApplication getApplication() {
		if (!application) {
			application = ApplicationHolder.application
		}
		application
	}
}
