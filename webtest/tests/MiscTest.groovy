class MiscTest extends AbstractSecurityWebTest {

	void testAll() {

		createRoles()
		createUsers()

		_testSaltedPassword()
		tearDown()

		_testSwitchUser()
		tearDown()

		_testHierarchicalRoles()
		tearDown()

		_testTaglibsUnauthenticated()
		tearDown()

		_testTaglibsUser()
		tearDown()

		_testTaglibsAdmin()
		tearDown()

		_testMetaclassMethodsUnauthenticated()
		tearDown()

		_testMetaclassMethodsAuthenticated()
		tearDown()

		_testHypenated()
	}

	void _testSaltedPassword() {

		String encryptedPassword = getContent('/hack/getUserProperty?user=user1&propName=password', true)

		def passwordEncoder = createSha256Encoder()

		String notSalted = passwordEncoder.encodePassword('p4ssw0rd', null)
		String salted = passwordEncoder.encodePassword('p4ssw0rd', 'user1')

		assertEquals salted, encryptedPassword
		assertFalse notSalted == encryptedPassword
	}

	void _testSwitchUser() {

		login 'user1', 'p4ssw0rd'

		// verify logged in
		get '/secure-annotated'
		assertContentContains 'you have ROLE_ADMIN'

		String auth = getSessionValue('SPRING_SECURITY_CONTEXT', sessionId)
		assertTrue auth.contains('Username:user1')
		assertTrue auth.contains('Authenticated:true')
		assertTrue auth.contains('ROLE_ADMIN')
		assertTrue auth.contains('ROLE_USER') // new, added since inferred from role hierarchy
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

		get '/secure-annotated/user-action'
		assertContentContains 'you have ROLE_USER'

		// verify not logged in as admin
		get '/secure-annotated/admin-either'
		assertContentContains "Sorry, you're not authorized to view this page."

		// switch back
		get '/j_spring_security_exit_user'
		assertContentContains 'Welcome to Grails'

		// verify logged in as admin
		get '/secure-annotated/admin-either'
		assertContentContains 'you have ROLE_ADMIN'

		auth = getSessionValue('SPRING_SECURITY_CONTEXT', sessionId)
		assertTrue auth.contains('Username:user1')
		assertTrue auth.contains('Authenticated:true')
		assertTrue auth.contains('ROLE_ADMIN')
		assertTrue auth.contains('ROLE_USER')
		assertFalse auth.contains('ROLE_PREVIOUS_ADMINISTRATOR')
	}

	void _testHierarchicalRoles() {

		login 'user1', 'p4ssw0rd'

		// verify logged in
		get '/secure-annotated'
		assertContentContains 'you have ROLE_ADMIN'

		String auth = getSessionValue('SPRING_SECURITY_CONTEXT', sessionId)
		assertTrue auth.contains('Authenticated:true')
		assertTrue auth.contains('ROLE_USER')

		// now get an action that's ROLE_USER only
		get '/secure-annotated/user-action'
		assertContentContains 'you have ROLE_USER'
	}

	void _testTaglibsUnauthenticated() {

		get '/tag-lib-test/test'

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

	void _testTaglibsUser() {

		login 'user2', 'p4ssw0rd2'

		get '/tag-lib-test/test'
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

	void _testTaglibsAdmin() {

		login 'user1', 'p4ssw0rd'

		get '/tag-lib-test/test'
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

	void _testMetaclassMethodsUnauthenticated() {
		get '/tag-lib-test/testMetaclassMethods'
		assertContentContains 'getPrincipal: org.springframework.security.core.userdetails.User'
		assertContentContains 'Username: __grails.anonymous.user__'
		assertContentContains 'Granted Authorities: ROLE_ANONYMOUS'
		assertContentContains 'isLoggedIn: false'
		assertContentContains 'loggedIn: false'
		assertContentContains 'getAuthenticatedUser: null'
		assertContentContains 'authenticatedUser: null'
	}

	void _testMetaclassMethodsAuthenticated() {

		login 'user1', 'p4ssw0rd'

		get '/tag-lib-test/testMetaclassMethods'
		assertContentContains 'getPrincipal: grails.plugin.springsecurity.userdetails.GrailsUser'
		assertContentContains 'principal: grails.plugin.springsecurity.userdetails.GrailsUser'
		assertContentContains 'Username: user1'
		assertContentContains 'isLoggedIn: true'
		assertContentContains 'loggedIn: true'
		assertContentContains 'getAuthenticatedUser: com.testapp.TestUser : '
		assertContentContains 'authenticatedUser: com.testapp.TestUser : '
	}

	void _testHypenated() {

		get '/foo-bar'
		assertContentContains 'Please Login'
		get '/foo-bar/index'
		assertContentContains 'Please Login'
		get '/foo-bar/bar-foo'
		assertContentContains 'Please Login'

		login 'user1', 'p4ssw0rd'

		get '/foo-bar'
		assertContentContains 'INDEX'
		get '/foo-bar/index'
		assertContentContains 'INDEX'
		get '/foo-bar/bar-foo'
		assertContentContains 'barFoo'
	}

	private void createRoles() {

		// admin
		get '/test-role'
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
		get '/test-role'
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
		get '/test-user'
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
		get '/test-user'
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
}
