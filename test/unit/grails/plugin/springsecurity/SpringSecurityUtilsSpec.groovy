package grails.plugin.springsecurity

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
	def setupSpec() {
		SpringSecurityUtils.setApplication(grailsApplication)
		defineBeans {
			dummyFilter(DummyFilter)
			firstDummy(DummyFilter)
			defaultFilterChain(DefaultSecurityFilterChain, AnyRequestMatcher.INSTANCE, firstDummy)
			springSecurityFilterChain(FilterChainProxy, defaultFilterChain)
		}
	}

	def "should retain existing chainmap"() {
		expect:
		SpringSecurityUtils.application != null
		SpringSecurityUtils.registerFilter("firstDummy", 100)
		SpringSecurityUtils.getOrderedFilters().each { order, filterName -> 
			 def filter = applicationContext.getBean(filterName)
			 SpringSecurityUtils.getConfiguredOrderedFilters()[order] = filter
		}
		SpringSecurityUtils.clientRegisterFilter("dummyFilter", 101)
		def filterChainMap = applicationContext.springSecurityFilterChain.filterChainMap
		def filters = filterChainMap.values()[0]
		filters.size() == 2
		filters[1] == applicationContext.dummyFilter
	}
}

class DummyFilter extends GenericFilterBean {
	void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) {}
}