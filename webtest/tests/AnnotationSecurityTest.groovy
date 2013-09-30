class AnnotationSecurityTest extends AbstractSecurityWebTest {

	void testAnnotationSecurity() {

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
		logout()
		assertContentContains 'Welcome to Grails'

		get '/secureAnnotated'
		assertContentContains 'Please Login'

		get '/secureAnnotated/index'
		assertContentContains 'Please Login'

		get '/secureAnnotated/adminEither'
		assertContentContains 'Please Login'

		get '/secureClassAnnotated'
		assertContentContains 'Please Login'

		get '/secureClassAnnotated/index'
		assertContentContains 'Please Login'

		get '/secureClassAnnotated/otherAction'
		assertContentContains 'Please Login'

		get '/secureClassAnnotated/admin2'
		assertContentContains 'Please Login'

		get '/secureAnnotated/indexMethod'
		assertContentContains 'Please Login'

		get '/secureAnnotated/adminEitherMethod'
		assertContentContains 'Please Login'

		get '/secureAnnotated/adminEitherMethod.xml'
		assertContentContains 'Please Login'

		get '/secureAnnotated/adminEitherMethod;jsessionid=5514B068198CC7DBF372713326E14C12'
		assertContentContains 'Please Login'
	}

	private void loginAndCheckAllAllowed() {
		loginAndCheckAllAllowedAdmin1()
		loginAndCheckAllAllowedAdmin2()
	}

	private void loginAndCheckAllAllowedAdmin1() {
		login 'admin1', 'password1'

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
		assertContentContains "Sorry, you're not authorized to view this page."

		get '/secureAnnotated/expression'
		assertContentContains 'OK'

		get '/secureAnnotated/indexMethod'
		assertContentContains 'you have ROLE_ADMIN'

		get '/secureAnnotated/adminEitherMethod'
		assertContentContains 'you have ROLE_ADMIN'

		get '/secureAnnotated/expressionMethod'
		assertContentContains 'OK'

		get '/secureAnnotated/closureMethod'
		assertContentContains 'OK'
	}

	private void loginAndCheckAllAllowedAdmin2() {
		logout()
		assertContentContains 'Welcome to Grails'

		login 'admin2', 'password2'

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

		get '/secureAnnotated/expression'
		assertContentContains "Sorry, you're not authorized to view this page."

		get '/secureAnnotated/indexMethod'
		assertContentContains 'you have ROLE_ADMIN'

		get '/secureAnnotated/adminEitherMethod'
		assertContentContains 'you have ROLE_ADMIN'

		get '/secureAnnotated/expressionMethod'
		assertContentContains "Sorry, you're not authorized to view this page."

		get '/secureAnnotated/closureMethod'
		assertContentContains "Sorry, you're not authorized to view this page."
	}
}
