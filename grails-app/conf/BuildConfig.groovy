grails.project.work.dir = 'target'
grails.project.docs.output.dir = 'docs/manual' // for backwards-compatibility, the docs are checked into gh-pages branch

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
		compile('org.springframework.security:spring-security-core:3.0.7.RELEASE') {
			transitive = false
		}

		compile('org.springframework.security:spring-security-web:3.0.7.RELEASE') {
			transitive = false
		}
	}

	plugins {

		build(':release:1.0.0.RC3') { export = false }

		// hackish using 'provided' but 'build' doesn't put it in the pom
		provided ':webxml:1.3.1'
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
