import com.testapp.TestUserPasswordEncoderListener
import grails.plugin.springsecurity.SpringSecurityUtils
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
}
