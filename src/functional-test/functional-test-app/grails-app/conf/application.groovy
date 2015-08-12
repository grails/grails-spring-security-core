grails {
	plugin {
		springsecurity {
			debug {
				useFilter = true
			}
			authority {
				className = 'com.testapp.TestRole'
			}
			password {
				algorithm = 'SHA-256'
			}
			rejectIfNoRule = false
			requestMap {
				className = 'com.testapp.TestRequestmap'
			}
			userLookup {
				authorityJoinClassName = 'com.testapp.TestUserTestRole'
				userDomainClassName = 'com.testapp.TestUser'
			}
			controllerAnnotations {
				staticRules = [
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
					'/assets/**':                     ['permitAll'],
					'/securityinfo':                  ['permitAll'],
					'/securityinfo/**':               ['permitAll']
				]
			}
		}
	}
}

def file = new File('testconfig')
String testconfig = file.exists() ? file.text.trim().toLowerCase() : ''
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
//		grails.web.url.converter = 'hyphenated'
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
			'/**': 'permitAll'
		]
		break
}
