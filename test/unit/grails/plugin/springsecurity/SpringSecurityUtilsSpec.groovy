package grails.plugin.springsecurity

import grails.test.mixin.TestMixin
import grails.test.mixin.support.GrailsUnitTestMixin

import javax.servlet.FilterChain
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse

import org.springframework.security.web.DefaultSecurityFilterChain
import org.springframework.security.web.FilterChainProxy
import org.springframework.security.web.util.matcher.AnyRequestMatcher
import org.springframework.web.filter.GenericFilterBean

import spock.lang.Specification

@TestMixin(GrailsUnitTestMixin)
class SpringSecurityUtilsSpec extends Specification {
	static def originalfilterChainMap

	def setupSpec() {
		SpringSecurityUtils.setApplication(grailsApplication)
		defineBeans {
			dummyFilter(DummyFilter)
			firstDummy(DummyFilter)
			secondDummy(DummyFilter)
			defaultFilterChain(DefaultSecurityFilterChain, AnyRequestMatcher.INSTANCE, [firstDummy, secondDummy])
			springSecurityFilterChain(FilterChainProxy, defaultFilterChain)
		}
		originalfilterChainMap = applicationContext.springSecurityFilterChain.filterChainMap
	}
	
	def setup() {
		SpringSecurityUtils.setApplication(grailsApplication)
		SpringSecurityUtils.registerFilter("firstDummy", 100)
		SpringSecurityUtils.registerFilter("secondDummy", 200)
		SpringSecurityUtils.getOrderedFilters().each { order, filterName -> 
			def filter = applicationContext.getBean(filterName)
			SpringSecurityUtils.getConfiguredOrderedFilters()[order] = filter
		}
		applicationContext.springSecurityFilterChain.filterChainMap = originalfilterChainMap
	}

	def "should retain existing chainmap"() {
		when:
		SpringSecurityUtils.clientRegisterFilter("dummyFilter", 101)
		then:
		def filterChainMap = applicationContext.springSecurityFilterChain.filterChainMap
		def filters = filterChainMap.values()[0]
		filters.size() == 3
		filters[1] == applicationContext.dummyFilter
	}
	
	def "should add as first in existing chainmap"() {
		when:
		SpringSecurityUtils.clientRegisterFilter("dummyFilter", 99)
		then:
		def filterChainMap = applicationContext.springSecurityFilterChain.filterChainMap
		def filters = filterChainMap.values()[0]
		filters.size() == 3
		filters[0] == applicationContext.dummyFilter
	}

	def "should add as last in existing chainmap"() {
		when:
		SpringSecurityUtils.clientRegisterFilter("dummyFilter", 201)
		then:
		def filterChainMap = applicationContext.springSecurityFilterChain.filterChainMap
		def filters = filterChainMap.values()[0]
		filters.size() == 3
		filters[2] == applicationContext.dummyFilter
	}
}

class DummyFilter extends GenericFilterBean {
	void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) {}
}