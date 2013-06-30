grails.project.work.dir = 'target'
grails.project.docs.output.dir = 'docs/manual' // for backwards-compatibility, the docs are checked into gh-pages branch
grails.project.source.level = 1.6

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
//			transitive = false
			excludes 'spring-expression', 'spring-core', 'spring-context', 'spring-tx',
			         'spring-aop', 'spring-jdbc', 'spring-web', 'spring-test', 'aspectjrt',
			         'aspectjweaver', 'cglib-nodep', 'ehcache', 'commons-collections',
			         'hsqldb', 'jsr250-api', 'log4j', 'junit', 'mockito-core', 'jmock-junit4'
		}

		compile('org.springframework.security:spring-security-web:3.0.7.RELEASE') {
//			transitive = false
			excludes 'spring-security-core', 'spring-web', 'spring-jdbc', 'spring-test',
			         'commons-codec', 'hsqldb', 'servlet-api', 'junit', 'mockito-core', 'jmock-junit4'
		}
	}

	plugins {
		// hackish using 'provided' but 'build' doesn't put it in the pom
		provided ':webxml:1.4.1'

		build(':release:2.0.3', ':rest-client-builder:1.0.2') {
			export = false
		}
	}
}
