grails.controllers.defaultScope = 'singleton'
grails.converters.encoding = 'UTF-8'
grails.enable.native2ascii = true
grails.exceptionresolver.params.exclude = ['password']
grails.hibernate.cache.queries = false
grails.hibernate.osiv.readonly = false
grails.hibernate.pass.readonly = false
grails.json.legacy.builder = false
grails.logging.jul.usebridge = true
grails.mime.disable.accept.header.userAgents = ['Gecko', 'WebKit', 'Presto', 'Trident']
grails.mime.types = [
	all:           '*/*',
	atom:          'application/atom+xml',
	css:           'text/css',
	csv:           'text/csv',
	form:          'application/x-www-form-urlencoded',
	html:          ['text/html','application/xhtml+xml'],
	js:            'text/javascript',
	json:          ['application/json', 'text/json'],
	multipartForm: 'multipart/form-data',
	rss:           'application/rss+xml',
	text:          'text/plain',
	hal:           ['application/hal+json','application/hal+xml'],
	xml:           ['text/xml', 'application/xml']
]
grails.project.groupId = appName
grails.resources.adhoc.includes = ['/images/**', '/css/**', '/js/**', '/plugins/**']
grails.resources.adhoc.patterns = ['/images/*', '/css/*', '/js/*', '/plugins/*']
grails.scaffolding.templates.domainSuffix = 'Instance'
grails.spring.bean.packages = []
grails.views.default.codec = 'html'
grails {
	views {
		gsp {
			encoding = 'UTF-8'
			htmlcodec = 'xml'
			codecs {
				expression = 'html'
				scriptlet = 'html'
				taglib = 'none'
				staticparts = 'none'
			}
		}
	}
}
grails.web.disable.multipart = false

environments {
	production {
		grails.logging.jul.usebridge = false
	}
}

log4j = {
	error 'org.codehaus.groovy.grails',
	      'org.springframework',
	      'org.hibernate',
	      'net.sf.ehcache.hibernate'
//	debug 'org.hibernate.SQL'
//	trace 'org.hibernate.type.descriptor.sql.BasicBinder'
}

grails.plugin.springsecurity.authority.className = 'com.testapp.TestRole'
grails.plugin.springsecurity.fii.rejectPublicInvocations = true
grails.plugin.springsecurity.password.algorithm = 'SHA-256'
grails.plugin.springsecurity.rejectIfNoRule = false
grails.plugin.springsecurity.requestMap.className = 'com.testapp.TestRequestmap'
grails.plugin.springsecurity.securityConfigType = 'Requestmap'
grails.plugin.springsecurity.userLookup.authorityJoinClassName = 'com.testapp.TestUserTestRole'
grails.plugin.springsecurity.userLookup.userDomainClassName = 'com.testapp.TestUser'
grails.plugin.springsecurity.controllerAnnotations.staticRules = [
	'/j_spring_security_switch_user': ['ROLE_ADMIN'],
	'/j_spring_security_exit_user':   ['permitAll'],
	'/':                              ['permitAll'],
	'/index':                         ['permitAll'],
	'/index.gsp':                     ['permitAll'],
	'/**/js/**':                      ['permitAll'],
	'/**/css/**':                     ['permitAll'],
	'/**/images/**':                  ['permitAll'],
	'/**/favicon.ico':                ['permitAll'],
	'/testData/**':                   ['permitAll'],
	'/dbconsole/**':                  ['permitAll'],
	'/dbconsole':                     ['permitAll'],
	'/assets/**':                     ['permitAll']
]

def file = new File('testconfig')
String testconfig = file.exists() ? file.text.trim() : ''
switch (testconfig) {
	case 'annotation':
		grails.plugin.springsecurity.securityConfigType = 'Annotation'
		break

	case 'basic':
		grails.plugin.springsecurity.securityConfigType = 'Annotation'
		grails.plugin.springsecurity.useBasicAuth = true
		grails.plugin.springsecurity.basic.realmName = 'Grails Spring Security Basic Test Realm'
		grails.plugin.springsecurity.filterChain.chainMap = [
			'/secureclassannotated/**': 'JOINED_FILTERS,-exceptionTranslationFilter',
			'/**': 'JOINED_FILTERS,-basicAuthenticationFilter,-basicExceptionTranslationFilter'
		]
		break

	case 'bcrypt':
		grails.plugin.springsecurity.securityConfigType = 'Annotation'
		grails.plugin.springsecurity.password.algorithm = 'bcrypt'
		break

	case 'misc':
		grails.plugin.springsecurity.securityConfigType = 'Annotation'
		grails.plugin.springsecurity.dao.reflectionSaltSourceProperty = 'username'
		grails.plugin.springsecurity.roleHierarchy = 'ROLE_ADMIN > ROLE_USER'
		grails.plugin.springsecurity.useSwitchUserFilter = true
		grails.plugin.springsecurity.failureHandler.exceptionMappings = [
			'org.springframework.security.authentication.LockedException':             '/testUser/accountLocked',
			'org.springframework.security.authentication.DisabledException':           '/testUser/accountDisabled',
			'org.springframework.security.authentication.AccountExpiredException':     '/testUser/accountExpired',
			'org.springframework.security.authentication.CredentialsExpiredException': '/testUser/passwordExpired'
		]
		grails.web.url.converter = 'hyphenated'
		break

	case 'requestmap':
		grails.plugin.springsecurity.securityConfigType = 'Requestmap'
		break

	case 'static':
		grails.plugin.springsecurity.securityConfigType = 'InterceptUrlMap'
		grails.plugin.springsecurity.interceptUrlMap = [
			'/secureannotated/admineither': ['ROLE_ADMIN', 'ROLE_ADMIN2'],
			'/secureannotated/expression': ["authentication.name == 'admin1'"],
			'/secureannotated/**': 'ROLE_ADMIN',
			'/**': 'IS_AUTHENTICATED_ANONYMOUSLY'
		]
		break
}
