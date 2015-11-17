if (System.getenv('TRAVIS_BRANCH')) {
	grails.project.repos.grailsCentral.username = System.getenv('GRAILS_CENTRAL_USERNAME')
	grails.project.repos.grailsCentral.password = System.getenv('GRAILS_CENTRAL_PASSWORD')
}
grails.project.work.dir = 'target'
grails.project.docs.output.dir = 'docs/manual' // for backwards-compatibility, the docs are checked into gh-pages branch

grails.project.dependency.resolver = 'maven'
grails.project.dependency.resolution = {

	inherits 'global'
	log 'warn'

	repositories {
		mavenLocal()
		grailsCentral()
		mavenCentral()
	}

	dependencies {

		String springSecurityVersion = '3.2.9.RELEASE'

		compile "org.springframework.security:spring-security-core:$springSecurityVersion", {
			excludes 'aopalliance', 'aspectjrt', 'cglib-nodep', 'commons-collections', 'commons-logging',
			         'ehcache', 'fest-assert', 'hsqldb', 'jcl-over-slf4j', 'jsr250-api', 'junit',
			         'logback-classic', 'mockito-core', 'powermock-api-mockito', 'powermock-api-support',
			         'powermock-core', 'powermock-module-junit4', 'powermock-module-junit4-common',
			         'powermock-reflect', 'spring-aop', 'spring-beans', 'spring-context', 'spring-core',
			         'spring-expression', 'spring-jdbc', 'spring-test', 'spring-tx'
		}

		compile "org.springframework.security:spring-security-web:$springSecurityVersion", {
			excludes 'aopalliance', 'commons-codec', 'commons-logging', 'fest-assert', 'groovy', 'hsqldb',
			         'jcl-over-slf4j', 'junit', 'logback-classic', 'mockito-core', 'powermock-api-mockito',
			         'powermock-api-support', 'powermock-core', 'powermock-module-junit4',
			         'powermock-module-junit4-common', 'powermock-reflect', 'spock-core', 'spring-beans',
			         'spring-context', 'spring-core', 'spring-expression', 'spring-jdbc',
			         'spring-security-core', 'spring-test', 'spring-tx', 'spring-web', 'spring-webmvc',
			         'tomcat-servlet-api'
		}

		compile 'net.sf.ehcache:ehcache:2.9.0'
	}

	plugins {
		compile ':webxml:1.4.1'

		build ':release:3.1.1', ':rest-client-builder:2.1.1', {
			export = false
		}

		compile ':hibernate:3.6.10.14', {
			export = false
		}
	}
}
