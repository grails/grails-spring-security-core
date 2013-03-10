// for testing only, not included in plugin zip

import org.springframework.security.authentication.LockedException
import org.springframework.security.authentication.DisabledException
import org.springframework.security.authentication.AccountExpiredException
import org.springframework.security.authentication.CredentialsExpiredException

grails {
	plugins {
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
			}

			authority {
				className = 'test.TestRole'
				nameField = 'auth'
			}

			rememberMe {
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
                '/testController/**':   ['roleInMap']
            ]
		}
	}
}

grails.doc.authors = 'Burt Beckwith, Beverley Talbott'
grails.doc.license = 'Apache License 2.0'
grails.doc.title = 'Spring Security Core Plugin'
