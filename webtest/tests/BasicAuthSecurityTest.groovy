class BasicAuthSecurityTest extends AbstractSecurityWebTest {

	void testBasicAuthSecurity() {

		createRoles()
		createUsers()

		checkSecuredUrlsNotVisibleWithoutAuth()
		checkSecuredUrlsVisibleWithAuth()
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

	private void checkSecuredUrlsNotVisibleWithoutAuth() {
		get '/logout'
		assertContentContains 'Welcome to Grails'

		// secureAnnotated is form auth

		get '/secureAnnotated'
		assertContentContains 'Please Login'

		get '/secureAnnotated/index'
		assertContentContains 'Please Login'

		get '/secureAnnotated/adminEither'
		assertContentContains 'Please Login'

		// secureAnnotated is basic auth

		get '/secureClassAnnotated'
		assertStatus 401

		get '/secureClassAnnotated/index'
		assertStatus 401

		get '/secureClassAnnotated/otherAction'
		assertStatus 401

		get '/secureClassAnnotated/admin2'
		assertStatus 401
	}

	private void checkSecuredUrlsVisibleWithAuth() {
		// Check with admin1 auth, some @Secure actions are accessible

		get '/secureAnnotated'
		assertContentContains 'Please Login'
		form {
			j_username = 'admin1'
			j_password = 'password1'
			_spring_security_remember_me = true
			clickButton 'Login'
		}
		assertContentContains 'you have ROLE_ADMIN'
		get '/logout'

		get '/secureAnnotated/index'
		assertContentContains 'Please Login'
		form {
			j_username = 'admin1'
			j_password = 'password1'
			_spring_security_remember_me = true
			clickButton 'Login'
		}
		assertContentContains 'you have ROLE_ADMIN'
		get '/logout'

		get '/secureAnnotated/adminEither'
		assertContentContains 'Please Login'
		form {
			j_username = 'admin1'
			j_password = 'password1'
			_spring_security_remember_me = true
			clickButton 'Login'
		}
		assertContentContains 'you have ROLE_ADMIN'
		get '/logout'

		getWithAuth '/secureClassAnnotated', 'admin1', 'password1'
		assertContentContains 'you have ROLE_ADMIN'
		get '/logout'

		getWithAuth '/secureClassAnnotated/index', 'admin1', 'password1'
		assertContentContains 'you have ROLE_ADMIN'
		get '/logout'

		getWithAuth '/secureClassAnnotated/otherAction', 'admin1', 'password1'
		assertContentContains 'you have ROLE_ADMIN'
		get '/logout'

		getWithAuth '/secureClassAnnotated/admin2', 'admin1', 'password1'
		assertStatus 403
		get '/logout'

		// now as admin2

		// Check that with admin2 auth, some @Secure actions are accessible

		get '/secureAnnotated'
		assertContentContains 'Please Login'
		form {
			j_username = 'admin2'
			j_password = 'password2'
			_spring_security_remember_me = true
			clickButton 'Login'
		}
		assertContentContains 'you have ROLE_ADMIN'
		get '/logout'

		get '/secureAnnotated/index'
		assertContentContains 'Please Login'
		form {
			j_username = 'admin2'
			j_password = 'password2'
			_spring_security_remember_me = true
			clickButton 'Login'
		}
		assertContentContains 'you have ROLE_ADMIN'
		get '/logout'

		get '/secureAnnotated/adminEither'
		assertContentContains 'Please Login'
		form {
			j_username = 'admin2'
			j_password = 'password2'
			_spring_security_remember_me = true
			clickButton 'Login'
		}
		assertContentContains 'you have ROLE_ADMIN'
		get '/logout'

		getWithAuth '/secureClassAnnotated', 'admin2', 'password2'
		assertContentContains 'index: you have ROLE_ADMIN'
		get '/logout'

		getWithAuth '/secureClassAnnotated/index', 'admin2', 'password2'
		assertContentContains 'index: you have ROLE_ADMIN'
		get '/logout'

		getWithAuth '/secureClassAnnotated/otherAction', 'admin2', 'password2'
		assertContentContains 'otherAction: you have ROLE_ADMIN'
		get '/logout'

		getWithAuth '/secureClassAnnotated/admin2', 'admin2', 'password2'
		assertContentContains 'admin2: you have ROLE_ADMIN2'
		get '/logout'
	}
}
