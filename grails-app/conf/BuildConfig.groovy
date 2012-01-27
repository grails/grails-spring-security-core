import grails.util.Metadata

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

		if (Metadata.current.getGrailsVersion()[0] != '1') {
			build(":hibernate:$grailsVersion") {
				export = false
				excludes 'dom4j'
			}
		}

		// hackish using 'provided' but 'build' doesn't put it in the pom
		provided ':webxml:1.4.1'
	}
}
