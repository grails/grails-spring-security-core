import org.springframework.security.authentication.AccountExpiredException
import org.springframework.security.authentication.CredentialsExpiredException
import org.springframework.security.authentication.DisabledException
import org.springframework.security.authentication.LockedException

dataSource {
	dbCreate = 'update'
	driverClassName = 'org.h2.Driver'
	jmxExport = false
	password = ''
	pooled = true
	url = 'jdbc:h2:mem:testDb;MVCC=TRUE;LOCK_TIMEOUT=10000;DB_CLOSE_ON_EXIT=FALSE'
	username = 'sa'
}

grails {
	plugin {
		springsecurity {
			userLookup {
				userDomainClassName = 'test.TestUser'
				usernamePropertyName = 'loginName'
				enabledPropertyName = 'enabld'
				passwordPropertyName = 'passwrrd'
				authoritiesPropertyName = 'roles'
				authorityJoinClassName = 'test.TestUserRole'
			}

			requestMap {
				className = 'test.TestRequestmap'
				urlField = 'urlPattern'
				configAttributeField = 'rolePattern'
				httpMethodField = 'httpMethod'
			}

			authority {
				className = 'test.TestRole'
				nameField = 'auth'
			}

			rememberMe {
				persistent = true
				persistentToken {
					domainClassName = 'test.TestPersistentLogin'
				}
			}

			failureHandler {
				exceptionMappings = [
					[exception: LockedException.name,             url: '/testUser/accountLocked'],
					[exception: DisabledException.name,           url: '/testUser/accountDisabled'],
					[exception: AccountExpiredException.name,     url: '/testUser/accountExpired'],
					[exception: CredentialsExpiredException.name, url: '/testUser/passwordExpired']
				]
			}
			interceptUrlMap = [
				[pattern: '/testController/**', access: ['roleInMap']]
			]

			logout {
				additionalHandlerNames = ['additionalLogoutHandler']
			}
		}
	}
}

hibernate {
	cache {
		queries = false
		use_query_cache = false
		use_second_level_cache = false
	}
	format_sql = true
	use_sql_comments = true
}

info {
	app {
		name = '@info.app.name@'
		version = '@info.app.version@'
		grailsVersion = '@info.app.grailsVersion@'
	}
}

spring.groovy.template.'check-template-location' = false
