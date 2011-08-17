grails.project.class.dir = 'target/classes'
grails.project.test.class.dir = 'target/test-classes'
grails.project.test.reports.dir = 'target/test-reports'
grails.project.docs.output.dir = 'docs' // for backwards-compatibility, the docs are checked into gh-pages branch

grails.project.dependency.resolution = {

	inherits 'global'

	log 'warn'

	repositories {
		grailsPlugins()
		grailsHome()
		grailsCentral()

		mavenCentral()
	}

	dependencies {
		compile('org.springframework.security:spring-security-core:3.0.5.RELEASE') {
			transitive = false
		}

		compile('org.springframework.security:spring-security-web:3.0.5.RELEASE') {
			transitive = false
		}
	}

	plugins {
		build(':release:1.0.0.RC3') {
			export = false
		}
	}
}

coverage {
	enabledByDefault = true
	sourceInclusions = ['grails-app/conf']
	exclusionListOverride = [
		'*GrailsPlugin*',
		'DataSource*',
		'*Config*',
		'test/**'
	]
}
