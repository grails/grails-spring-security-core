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
package grails.plugins.springsecurity

import org.codehaus.groovy.grails.plugins.springsecurity.SpringSecurityUtils

class SecurityTagLib {

	static namespace = 'sec'

	def springSecurityService

	def ifAllGranted = { attrs, body ->

		assertAttribute 'roles', attrs, 'ifAllGranted'

		if (SpringSecurityUtils.ifAllGranted(attrs.roles)) {
			out << body()
		}
	}

	def ifNotGranted = { attrs, body ->

		assertAttribute 'roles', attrs, 'ifNotGranted'

		if (SpringSecurityUtils.ifNotGranted(attrs.roles)) {
			out << body()
		}
	}

	def ifAnyGranted = { attrs, body ->

		assertAttribute 'roles', attrs, 'ifAnyGranted'

		if (SpringSecurityUtils.ifAnyGranted(attrs.roles)) {
			out << body()
		}
	}

	// TODO rename
	// TODO support 'var' and 'scope' and set the result instead of writing it
	def loggedInUserInfo = { attrs, body ->

		assertAttribute 'field', attrs, 'loggedInUserInfo'

		def source
		if (springSecurityService.isLoggedIn()) {
			source = determineSource()
			for (pathElement in attrs.field.split('\\.')) {
				source = source."$pathElement"
				if (source == null) {
					break
				}
			}
		}

		if (source) {
			out << source
		}
		else {
			out << body()
		}
	}

	def username = { attrs ->
		if (springSecurityService.isLoggedIn()) {
			out << springSecurityService.principal.username
		}
	}

	def ifLoggedIn = { attrs, body ->
		if (springSecurityService.isLoggedIn()) {
			out << body()
		}
	}

	def ifNotLoggedIn = { attrs, body ->
		if (!springSecurityService.isLoggedIn()) {
			out << body()
		}
	}

	private void assertAttribute(String name, attrs, String tag) {
		if (!attrs[name]) {
			throwTagError "Tag [$tag] is missing required attribute [$name]"
		}
	}

	// TODO not supporting getDomainClass?
	private determineSource() {
		def principal = springSecurityService.principal

		// check to see if it's a GrailsUser/GrailsUserImpl/subclass,
		// or otherwise has a 'domainClass' property
		if (principal.metaClass.respondsTo(principal, 'getDomainClass')) {
			return principal.domainClass
		}

		principal
	}
}
