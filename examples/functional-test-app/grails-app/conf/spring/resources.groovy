package spring

import com.testapp.MaintenanceModeFilter
import com.testapp.TestUserPasswordEncoderListener
import grails.plugin.springsecurity.SpringSecurityUtils
import org.springframework.boot.web.servlet.FilterRegistrationBean
import test.TestRequestmapFilterInvocationDefinition

beans = {
    testUserPasswordEncoderListener(TestUserPasswordEncoderListener)
	if (SpringSecurityUtils.securityConfigType == 'Requestmap') {
		objectDefinitionSource(TestRequestmapFilterInvocationDefinition) {
			def reject = SpringSecurityUtils.securityConfig.rejectIfNoRule
			if (reject instanceof Boolean) {
				rejectIfNoRule = reject
			}
		}
	}

	String testconfig = System.getProperty('TESTCONFIG')
	if (testconfig == 'issue503') {
		maintenanceModeFilter(MaintenanceModeFilter)
		maintenanceModeFilterDeregistrationBean(FilterRegistrationBean) {
			filter = ref("maintenanceModeFilter")
			enabled = false
		}
	}
}
