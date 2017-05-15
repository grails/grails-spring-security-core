import org.springframework.security.authentication.AccountExpiredException
import org.springframework.security.authentication.CredentialsExpiredException
import org.springframework.security.authentication.DisabledException
import org.springframework.security.authentication.LockedException

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



