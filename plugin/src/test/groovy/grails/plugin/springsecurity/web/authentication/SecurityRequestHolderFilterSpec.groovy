/* Copyright 2006-2016 the original author or authors.
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
package grails.plugin.springsecurity.web.authentication

import grails.plugin.springsecurity.AbstractUnitSpec
import grails.plugin.springsecurity.web.SecurityRequestHolder
import grails.plugin.springsecurity.web.SecurityRequestHolderFilter

import jakarta.servlet.FilterChain

/**
 * @author Burt Beckwith
 */
class SecurityRequestHolderFilterSpec extends AbstractUnitSpec {

	private SecurityRequestHolderFilter filter = new SecurityRequestHolderFilter()

	void 'doFilter'() {
		expect:
		!SecurityRequestHolder.request
		!SecurityRequestHolder.response

		when:
		boolean chainCalled = false
		def chain = [doFilter: { req, res ->
			assert SecurityRequestHolder.request
			assert SecurityRequestHolder.response
			chainCalled = true
		}] as FilterChain

		filter.doFilter request, response, chain

		then:
		chainCalled
		!SecurityRequestHolder.request
		!SecurityRequestHolder.response
	}
}
