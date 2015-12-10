import grails.core.GrailsApplication
import grails.core.GrailsControllerClass
import grails.plugin.springsecurity.SpringSecurityUtils
import grails.plugin.springsecurity.web.access.intercept.AnnotationFilterInvocationDefinition
import org.springframework.cglib.reflect.FastMethod
import test.HackUrlConverter

class BootStrap {

	GrailsApplication grailsApplication
	TestDataService testDataService
	HackUrlConverter grailsUrlConverter
	def grailsUrlMappingsHolder
	def objectDefinitionSource

	def init = {
		testDataService.enterInitialData()

		if (grailsApplication.config.grails.web.url.converter == 'hyphenated') {
			fixHyphenation()
		}
	}

	// workaround for issue #9431
	private void fixHyphenation() {

		// switch to the real converter
		grailsUrlConverter.useHyphenated()

		// re-register the controllers so the urls are correct
		for (GrailsControllerClass cc in grailsApplication.controllerClasses) {
			Map<String, FastMethod> actionsMap = cc.@actions
			List<String> actionNames = cc.actions as List
			for (String actionName in actionNames) {
				actionsMap[grailsUrlConverter.toUrlElement(actionName)] = actionsMap.remove(actionName)
			}

			cc.registerUrlConverter grailsUrlConverter
			grailsUrlMappingsHolder.registerController cc
		}

		if (SpringSecurityUtils.securityConfigType == 'Annotation') {
			// redo annotation parsing so the correct urls are used
			AnnotationFilterInvocationDefinition afid = objectDefinitionSource
			afid.initialize SpringSecurityUtils.securityConfig.controllerAnnotations.staticRules, grailsUrlMappingsHolder,
					grailsApplication.controllerClasses, grailsApplication.domainClasses
		}
	}
}
