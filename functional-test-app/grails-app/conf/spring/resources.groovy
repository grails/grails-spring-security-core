import grails.plugin.springsecurity.SpringSecurityUtils
import grails.web.UrlConverter
import test.HackUrlConverter
import test.TestRequestmapFilterInvocationDefinition

beans = {
	"$UrlConverter.BEAN_NAME"(HackUrlConverter)

	String securityConfigType = SpringSecurityUtils.securityConfigType
	def conf = SpringSecurityUtils.securityConfig

	if (securityConfigType == 'Requestmap') {
		objectDefinitionSource(TestRequestmapFilterInvocationDefinition) {
			if (conf.rejectIfNoRule instanceof Boolean) {
				rejectIfNoRule = conf.rejectIfNoRule
			}
		}
	}
}
