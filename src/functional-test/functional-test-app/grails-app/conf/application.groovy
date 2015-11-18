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
					[pattern: '/j_spring_security_switch_user', access: ['ROLE_ADMIN']],
					[pattern: '/j_spring_security_exit_user',   access: ['permitAll']],
					[pattern: '/',                              access: ['permitAll']],
					[pattern: '/error':,                        access: ['permitAll']],
					[pattern: '/index':,                        access: ['permitAll']],
					[pattern: '/index.gsp':,                    access: ['permitAll']],
					[pattern: '/shutdown':,                     access: ['permitAll']],
					[pattern: '/**/js/**':,                     access: ['permitAll']],
					[pattern: '/**/css/**':,                    access: ['permitAll']],
					[pattern: '/**/images/**':,                 access: ['permitAll']],
					[pattern: '/**/favicon.ico':,               access: ['permitAll']],
					[pattern: '/testData/**':,                  access: ['permitAll']],
					[pattern: '/dbconsole/**':,                 access: ['permitAll']],
					[pattern: '/dbconsole':,                    access: ['permitAll']],
					[pattern: '/assets/**':,                    access: ['permitAll']],
					[pattern: '/securityinfo':,                 access: ['permitAll']],
					[pattern: '/securityinfo/**':,              access: ['permitAll']]
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
			[exception: 'org.springframework.security.authentication.LockedException',             url: '/testUser/accountLocked'],
			[exception: 'org.springframework.security.authentication.DisabledException',           url: '/testUser/accountDisabled'],
			[exception: 'org.springframework.security.authentication.AccountExpiredException',     url: '/testUser/accountExpired'],
			[exception: 'org.springframework.security.authentication.CredentialsExpiredException', url: '/testUser/passwordExpired']
		]
//		grails.web.url.converter = 'hyphenated'
		break

	case 'requestmap':
		grails.plugin.springsecurity.securityConfigType = 'Requestmap'
		break

	case 'static':
		grails.plugin.springsecurity.securityConfigType = 'InterceptUrlMap'
		grails.plugin.springsecurity.interceptUrlMap = [
			[pattern: '/secureannotated/admineither', access: ['ROLE_ADMIN', 'ROLE_ADMIN2']],
			[pattern: '/secureannotated/expression',  access: ["authentication.name == 'admin1'"]],
			[pattern: '/secureannotated/**',          access: 'ROLE_ADMIN'],
			[pattern: '/**',                          access: 'permitAll']
		]
		break
}
