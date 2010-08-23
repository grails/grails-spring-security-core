import org.springframework.security.authentication.encoding.MessageDigestPasswordEncoder

class MiscTest extends AbstractSecurityWebTest {

	void testSaltedPassword() {
		createRoles()
		createUsers()

		String encryptedPassword = getContent('/hack/getUserProperty?user=user1&propName=password', true)

		def passwordEncoder = new MessageDigestPasswordEncoder('SHA-256')
		String notSalted = passwordEncoder.encodePassword('p4ssw0rd', null)
		String salted = passwordEncoder.encodePassword('p4ssw0rd', 'user1')

		assertEquals salted, encryptedPassword
		assertFalse notSalted == encryptedPassword
	}

	private void createRoles() {

		// admin
		get '/testRole'
		verifyListSize 0

		click 'New TestRole'
		assertContentContains 'Create TestRole'

		form {
			authority = 'ROLE_ADMIN'
		}
		clickButton 'Create'

		assertContentContains 'Show TestRole'
		click 'TestRole List'
		verifyListSize 1

		// user
		get '/testRole'
		click 'New TestRole'
		assertContentContains 'Create TestRole'

		form {
			authority = 'ROLE_USER'
		}
		clickButton 'Create'

		assertContentContains 'Show TestRole'
		click 'TestRole List'
		verifyListSize 2
	}

	private void createUsers() {

		// user1
		get '/testUser'
		verifyListSize 0

		click 'New TestUser'
		assertContentContains 'Create TestUser'

		form {
			username = 'user1'
			password = 'p4ssw0rd'
			enabled = true
			ROLE_ADMIN = true
		}
		clickButton 'Create'

		assertContentContains 'Show TestUser'
		click 'TestUser List'
		verifyListSize 1

		// user2
		get '/testUser'
		click 'New TestUser'
		assertContentContains 'Create TestUser'

		form {
			username = 'user2'
			password = 'p4ssw0rd2'
			enabled = true
			ROLE_USER = true
		}
		clickButton 'Create'

		assertContentContains 'Show TestUser'
		click 'TestUser List'
		verifyListSize 2
	}

	void testSwitchUser() {

		// login as user1
		get '/login/auth'
		assertContentContains 'Please Login'

		form {
			j_username = 'user1'
			j_password = 'p4ssw0rd'
			_spring_security_remember_me = true
			clickButton 'Login'
		}

		// verify logged in
		get '/secureAnnotated'
		assertContentContains 'you have ROLE_ADMIN'

		String auth = getSessionValue('SPRING_SECURITY_CONTEXT', sessionId)
		assertTrue auth.contains('Username:user1')
		assertTrue auth.contains('Authenticated:true')
		assertTrue auth.contains('ROLE_ADMIN')
		assertFalse auth.contains('ROLE_USER')
		assertFalse auth.contains('ROLE_PREVIOUS_ADMINISTRATOR')

		// switch
		get '/j_spring_security_switch_user?j_username=user2'
		assertContentContains 'Welcome to Grails'

		// verify logged in as user1

		auth = getSessionValue('SPRING_SECURITY_CONTEXT', sessionId)
		assertTrue auth.contains('Username:user2')
		assertTrue auth.contains('Authenticated:true')
		assertTrue auth.contains('ROLE_USER')
		assertTrue auth.contains('ROLE_PREVIOUS_ADMINISTRATOR')

		get '/secureAnnotated/userAction'
		assertContentContains 'you have ROLE_USER'

		// verify not logged in as admin
		get '/secureAnnotated/adminEither'
		assertContentContains "Sorry, you're not authorized to view this page."

		// switch back
		get '/j_spring_security_exit_user'
		assertContentContains 'Welcome to Grails'

		// verify logged in as admin
		get '/secureAnnotated/adminEither'
		assertContentContains 'you have ROLE_ADMIN'

		auth = getSessionValue('SPRING_SECURITY_CONTEXT', sessionId)
		assertTrue auth.contains('Username:user1')
		assertTrue auth.contains('Authenticated:true')
		assertTrue auth.contains('ROLE_ADMIN')
		assertFalse auth.contains('ROLE_USER')
		assertFalse auth.contains('ROLE_PREVIOUS_ADMINISTRATOR')
	}

	void testHierarchicalRoles() {

		// login as user1
		get '/login/auth'
		assertContentContains 'Please Login'

		form {
			j_username = 'user1'
			j_password = 'p4ssw0rd'
			_spring_security_remember_me = true
			clickButton 'Login'
		}

		// verify logged in
		get '/secureAnnotated'
		assertContentContains 'you have ROLE_ADMIN'

		String auth = getSessionValue('SPRING_SECURITY_CONTEXT', sessionId)
		assertTrue auth.contains('Authenticated:true')
		assertFalse auth.contains('ROLE_USER')

		// now get an action that's ROLE_USER only
		get '/secureAnnotated/userAction'
		assertContentContains 'you have ROLE_USER'
	}

	void testTaglibsUnauthenticated() {

		get '/tagLibTest/test'

		assertContentDoesNotContain 'user and admin'
		assertContentDoesNotContain 'user and admin and foo'
		assertContentContains 'not user and not admin'
		assertContentDoesNotContain 'user or admin'
		assertContentContains 'accountNonExpired: "not logged in"'
		assertContentContains 'id: "not logged in"'
		assertContentContains 'Username is ""'
		assertContentDoesNotContain 'logged in true'
		assertContentContains 'logged in false'
		assertContentDoesNotContain 'switched true'
		assertContentContains 'switched false'
		assertContentContains 'switched original username ""'
		assertContentDoesNotContain 'access with role user: true'
		assertContentDoesNotContain 'access with role admin: true'
		assertContentContains 'access with role user: false'
		assertContentContains 'access with role admin: false'
	}

	void testTaglibsUser() {

		get '/login/auth'
		assertContentContains 'Please Login'

		form {
			j_username = 'user2'
			j_password = 'p4ssw0rd2'
			_spring_security_remember_me = true
			clickButton 'Login'
		}

		get '/tagLibTest/test'
		assertContentDoesNotContain 'user and admin'
		assertContentDoesNotContain 'user and admin and foo'
		assertContentDoesNotContain 'not user and not admin'
		assertContentContains 'user or admin'
		assertContentContains 'accountNonExpired: "true"'
		assertContentDoesNotContain 'id: "not logged in"' // can't test on exact id, don't know what it is
		assertContentContains 'Username is "user2"'
		assertContentContains 'logged in true'
		assertContentDoesNotContain 'logged in false'
		assertContentDoesNotContain 'switched true'
		assertContentContains 'switched false'
		assertContentContains 'switched original username ""'

		assertContentContains 'access with role user: true'
		assertContentDoesNotContain 'access with role admin: true'
		assertContentDoesNotContain 'access with role user: false'
		assertContentContains 'access with role admin: false'

		assertContentContains 'Can access /login/auth'
		assertContentDoesNotContain 'Can access /secureAnnotated'
		assertContentDoesNotContain 'Cannot access /login/auth'
		assertContentContains 'Cannot access /secureAnnotated'
	}

	void testTaglibsAdmin() {

		get '/login/auth'
		assertContentContains 'Please Login'

		form {
			j_username = 'user1'
			j_password = 'p4ssw0rd'
			_spring_security_remember_me = true
			clickButton 'Login'
		}

		get '/tagLibTest/test'
		assertContentContains 'user and admin'
		assertContentDoesNotContain 'user and admin and foo'
		assertContentDoesNotContain 'not user and not admin'
		assertContentContains 'user or admin'
		assertContentContains 'accountNonExpired: "true"'
		assertContentDoesNotContain 'id: "not logged in"' // can't test on exact id, don't know what it is
		assertContentContains 'Username is "user1"'

		assertContentContains 'logged in true'
		assertContentDoesNotContain 'logged in false'
		assertContentDoesNotContain 'switched true'
		assertContentContains 'switched false'
		assertContentContains 'switched original username ""'

		assertContentContains 'access with role user: true'
		assertContentContains 'access with role admin: true'
		assertContentDoesNotContain 'access with role user: false'
		assertContentDoesNotContain 'access with role admin: false'

		assertContentContains 'Can access /login/auth'
		assertContentContains 'Can access /secureAnnotated'
		assertContentDoesNotContain 'Cannot access /login/auth'
		assertContentDoesNotContain 'Cannot access /secureAnnotated'
	}

	void testMetaclassMethodsUnauthenticated() {
		get '/tagLibTest/testMetaclassMethods'
		assertContentContains 'getPrincipal: anonymousUser'
		assertContentContains 'principal: anonymousUser'
		assertContentContains 'isLoggedIn: false'
		assertContentContains 'loggedIn: false'
		assertContentContains 'getAuthenticatedUser: null'
		assertContentContains 'authenticatedUser: null'
	}

	void testMetaclassMethodsAuthenticated() {

		get '/login/auth'
		assertContentContains 'Please Login'

		form {
			j_username = 'user1'
			j_password = 'p4ssw0rd'
			_spring_security_remember_me = true
			clickButton 'Login'
		}

		get '/tagLibTest/testMetaclassMethods'
		assertContentContains 'getPrincipal: org.codehaus.groovy.grails.plugins.springsecurity.GrailsUser'
		assertContentContains 'principal: org.codehaus.groovy.grails.plugins.springsecurity.GrailsUser'
		assertContentContains 'Username: user1'
		assertContentContains 'isLoggedIn: true'
		assertContentContains 'loggedIn: true'
		assertContentContains 'getAuthenticatedUser: com.testapp.TestUser : '
		assertContentContains 'authenticatedUser: com.testapp.TestUser : '
	}
}
