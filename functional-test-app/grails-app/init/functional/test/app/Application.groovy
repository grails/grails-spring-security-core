package functional.test.app

import grails.boot.GrailsApp
import grails.boot.config.GrailsAutoConfiguration

class Application extends GrailsAutoConfiguration {

	static {
		ExpandoMetaClass.enableGlobally()
	}

	static void main(String[] args) {
		GrailsApp.run Application, args
	}
}
