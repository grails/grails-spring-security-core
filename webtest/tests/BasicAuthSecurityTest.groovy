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
		assertContentContains  'Create TestRole'

		form {
			authority = 'ROLE_ADMIN'
			clickButton 'Create'
		}

		assertContentContains 'Show TestRole'
		click 'TestRole List'

		verifyListSize 1

		click 'New TestRole'
		assertContentContains  'Create TestRole'

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
		assertContentContains  'Create TestUser'

		form {
			username = 'admin1'
			password = 'password1'
			enabled = true
			ROLE_ADMIN = true
			clickButton 'Create'
		}

		assertContentContains  'Show TestUser'
		click 'TestUser List'

		verifyListSize 1

		click 'New TestUser'
		assertContentContains  'Create TestUser'

		form {
			username = 'admin2'
			password = 'password2'
			enabled = true
			ROLE_ADMIN = true
			ROLE_ADMIN2 = true
			clickButton 'Create'
		}

		assertContentContains  'Show TestUser'
		click 'TestUser List'

		verifyListSize 2
	}

	private void checkSecuredUrlsNotVisibleWithoutAuth() {
		get '/logout'
		assertContentContains 'Welcome to Grails'

		get '/secureAnnotated'
		assertStatus 401

		get '/secureAnnotated/index'
		assertStatus 401

		get '/secureAnnotated/adminEither'
		assertStatus 401

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
		getWithAuth '/secureAnnotated', 'admin1', 'password1'
		assertContentContains 'you have ROLE_ADMIN'

		getWithAuth '/secureAnnotated/index', 'admin1', 'password1'
		assertContentContains 'you have ROLE_ADMIN'

		getWithAuth '/secureAnnotated/adminEither', 'admin1', 'password1'
		assertContentContains 'you have ROLE_ADMIN'

		getWithAuth '/secureClassAnnotated', 'admin1', 'password1'
		assertContentContains 'you have ROLE_ADMIN'

		getWithAuth '/secureClassAnnotated/index', 'admin1', 'password1'
		assertContentContains 'you have ROLE_ADMIN'

		getWithAuth '/secureClassAnnotated/otherAction', 'admin1', 'password1'
		assertContentContains 'you have ROLE_ADMIN'

		getWithAuth '/secureClassAnnotated/admin2', 'admin1', 'password1'
		assertContentContains "Sorry, you're not authorized to view this page."

		// login as admin2
		get '/logout'
		assertContentContains 'Welcome to Grails'

		// Check that with admin2 auth, some @Secure actions are accessible
		getWithAuth '/secureAnnotated', 'admin2', 'password2'
		assertContentContains 'you have ROLE_ADMIN'

		getWithAuth '/secureAnnotated/index', 'admin2', 'password2'
		assertContentContains 'you have ROLE_ADMIN'

		getWithAuth '/secureAnnotated/adminEither', 'admin2', 'password2'
		assertContentContains 'you have ROLE_ADMIN'

		getWithAuth '/secureClassAnnotated', 'admin2', 'password2'
		assertContentContains 'index: you have ROLE_ADMIN'

		getWithAuth '/secureClassAnnotated/index', 'admin2', 'password2'
		assertContentContains 'index: you have ROLE_ADMIN'

		getWithAuth '/secureClassAnnotated/otherAction', 'admin2', 'password2'
		assertContentContains 'otherAction: you have ROLE_ADMIN'

		getWithAuth '/secureClassAnnotated/admin2', 'admin2', 'password2'
		assertContentContains 'admin2: you have ROLE_ADMIN2'
	}
}
