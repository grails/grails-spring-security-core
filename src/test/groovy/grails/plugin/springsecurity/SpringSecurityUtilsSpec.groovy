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
package grails.plugin.springsecurity

import javax.servlet.FilterChain
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse

import org.springframework.security.web.DefaultSecurityFilterChain
import org.springframework.security.web.FilterChainProxy
import org.springframework.security.web.util.matcher.AnyRequestMatcher
import org.springframework.web.filter.GenericFilterBean

import grails.test.mixin.TestMixin
import grails.test.mixin.support.GrailsUnitTestMixin
import spock.lang.Specification

@TestMixin(GrailsUnitTestMixin)
class SpringSecurityUtilsSpec extends Specification {

	private static originalfilterChainMap

	def setupSpec() {
		SpringSecurityUtils.setApplication grailsApplication
		defineBeans {
			dummyFilter(DummyFilter)
			firstDummy(DummyFilter)
			secondDummy(DummyFilter)
			defaultFilterChain(DefaultSecurityFilterChain, AnyRequestMatcher.INSTANCE, [ref('firstDummy'), ref('secondDummy')])
			springSecurityFilterChain(FilterChainProxy, ref('defaultFilterChain'))
		}
		originalfilterChainMap = applicationContext.springSecurityFilterChain.filterChainMap
	}

	def setup() {
		SpringSecurityUtils.setApplication grailsApplication
		SpringSecurityUtils.registerFilter 'firstDummy', 100
		SpringSecurityUtils.registerFilter 'secondDummy', 200
		def configured = SpringSecurityUtils.configuredOrderedFilters
		SpringSecurityUtils.orderedFilters.each { order, name -> configured[order] = applicationContext.getBean(name) }
		applicationContext.springSecurityFilterChain.filterChainMap = originalfilterChainMap
	}

	def 'should retain existing chainmap'() {
		when:
			SpringSecurityUtils.clientRegisterFilter 'dummyFilter', 101
			def filterChainMap = applicationContext.springSecurityFilterChain.filterChainMap
			def filters = filterChainMap.values()[0]

		then:
			filters.size() == 3
			filters[1] == applicationContext.dummyFilter
	}

	def 'should add as first in existing chainmap'() {

		when:
			SpringSecurityUtils.clientRegisterFilter 'dummyFilter', 99
			def filterChainMap = applicationContext.springSecurityFilterChain.filterChainMap
			def filters = filterChainMap.values()[0]

		then:
			filters.size() == 3
			filters[0] == applicationContext.dummyFilter
	}

	def 'should add as last in existing chainmap'() {

		when:
			SpringSecurityUtils.clientRegisterFilter 'dummyFilter', 201
			def filterChainMap = applicationContext.springSecurityFilterChain.filterChainMap
			def filters = filterChainMap.values()[0]

		then:
			filters.size() == 3
			filters[2] == applicationContext.dummyFilter
	}
}

class DummyFilter extends GenericFilterBean {
	void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) {}
}
