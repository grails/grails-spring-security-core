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
					(LockedException.name): '/testUser/accountLocked',
					(DisabledException.name): '/testUser/accountDisabled',
					(AccountExpiredException.name): '/testUser/accountExpired',
					(CredentialsExpiredException.name): '/testUser/passwordExpired'
				]
			}
			interceptUrlMap = [
				'/testController/**': ['roleInMap']
			]

			logout {
				additionalHandlerNames = ['additionalLogoutHandler']
			}
 		}
	}
}
