class StaticSecurityTest extends AbstractSecurityWebTest {

	void testStaticSecurity() {
		createRoles()
		createUsers()
		checkSecuredUrlsNotVisibleWithoutLogin()
		loginAndCheckAllAllowed()
	}

	private void createRoles() {
		get '/testRole'
		assertContentContains 'Home'

		verifyListSize 0

		click 'New TestRole'
		assertContentContains 'Create TestRole'

		form {
			authority = 'ROLE_ADMIN'
			clickButton 'Create'
		}

		assertContentContains 'Show TestRole'
		click 'TestRole List'

		verifyListSize 1

		click 'New TestRole'
		assertContentContains 'Create TestRole'

		form {
			authority = 'ROLE_ADMIN2'
			clickButton 'Create'
		}

		assertContentContains 'Show TestRole'
		click 'TestRole List'

		verifyListSize 2
	}

	private void createUsers() {
		get '/testUser'
		assertContentContains 'Home'

		verifyListSize 0

		click 'New TestUser'
		assertContentContains 'Create TestUser'

		form {
			username = 'admin1'
			password = 'password1'
			enabled = true
			ROLE_ADMIN = true
			clickButton 'Create'
		}

		assertContentContains 'Show TestUser'
		click 'TestUser List'

		verifyListSize 1

		click 'New TestUser'
		assertContentContains 'Create TestUser'

		form {
			username = 'admin2'
			password = 'password2'
			enabled = true
			ROLE_ADMIN = true
			ROLE_ADMIN2 = true
			clickButton 'Create'
		}

		assertContentContains 'Show TestUser'
		click 'TestUser List'

		verifyListSize 2
	}

	private void checkSecuredUrlsNotVisibleWithoutLogin() {
		get '/logout'
		assertContentContains 'Welcome to Grails'

		get '/secureAnnotated'
		assertContentContains 'Please Login'

		get '/secureAnnotated/index'
		assertContentContains 'Please Login'

		get '/secureAnnotated/adminEither'
		assertContentContains 'Please Login'

		get '/secureClassAnnotated'
		assertContentContains 'index: you have ROLE_ADMIN'

		get '/secureClassAnnotated/index'
		assertContentContains 'index: you have ROLE_ADMIN'

		get '/secureClassAnnotated/otherAction'
		assertContentContains 'otherAction: you have ROLE_ADMIN'

		get '/secureClassAnnotated/admin2'
		assertContentContains 'admin2: you have ROLE_ADMIN2'
	}

	private void loginAndCheckAllAllowed() {
		// login as admin1
		get '/login/auth'
		assertContentContains 'Please Login'

		form {
			j_username = 'admin1'
			j_password = 'password1'
			_spring_security_remember_me = true
			clickButton 'Login'
		}

		// Check that after login as admin1, some @Secure actions are accessible
		get '/secureAnnotated'
		assertContentContains 'you have ROLE_ADMIN'

		get '/secureAnnotated/index'
		assertContentContains 'you have ROLE_ADMIN'

		get '/secureAnnotated/adminEither'
		assertContentContains 'you have ROLE_ADMIN'

		get '/secureClassAnnotated'
		assertContentContains 'you have ROLE_ADMIN'

		get '/secureClassAnnotated/index'
		assertContentContains 'you have ROLE_ADMIN'

		get '/secureClassAnnotated/otherAction'
		assertContentContains 'you have ROLE_ADMIN'

		get '/secureClassAnnotated/admin2'
		assertContentContains "admin2: you have ROLE_ADMIN2"

		// login as admin2
		get '/logout'
		assertContentContains 'Welcome to Grails'

		get '/login/auth'
		assertContentContains 'Please Login'

		form {
			j_username = 'admin2'
			j_password = 'password2'
			_spring_security_remember_me = true
			clickButton 'Login'
		}

		// Check that after login as admin2, some @Secure actions are accessible
		get '/secureAnnotated'
		assertContentContains 'you have ROLE_ADMIN'

		get '/secureAnnotated/index'
		assertContentContains 'you have ROLE_ADMIN'

		get '/secureAnnotated/adminEither'
		assertContentContains 'you have ROLE_ADMIN'

		get '/secureClassAnnotated'
		assertContentContains 'index: you have ROLE_ADMIN'

		get '/secureClassAnnotated/index'
		assertContentContains 'index: you have ROLE_ADMIN'

		get '/secureClassAnnotated/otherAction'
		assertContentContains 'otherAction: you have ROLE_ADMIN'

		get '/secureClassAnnotated/admin2'
		assertContentContains 'admin2: you have ROLE_ADMIN2'
	}
}
