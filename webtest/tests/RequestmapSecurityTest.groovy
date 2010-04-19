class RequestmapSecurityTest extends AbstractSecurityWebTest {

	void testUserListNewDelete() {

		checkSecurePageVisibleWithoutRequestmap()

		createRole()
		createUser()

		createRequestMap()
		checkSecurePageNotVisibleWithRequestmap()

		loginAndCheckAllAllowed()
	}

	private void createRole() {
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
	}

	private void createUser() {
		get '/testUser'
		assertContentContains'Home'

		verifyListSize 0

		click 'New TestUser'
		assertContentContains 'Create TestUser'

		form {
			username = 'new_user'
			password = 'p4ssw0rd'
			enabled = true
			ROLE_ADMIN = true
			clickButton 'Create'
		}

		assertContentContains 'Show TestUser'
		click 'TestUser List'

		verifyListSize 1
	}

	private void checkSecurePageVisibleWithoutRequestmap() {
		get '/secure'
		assertContentContains 'SECURE'
	}

	private void createRequestMap() {
		get '/testRequestmap'
		assertContentContains 'Home'

		verifyListSize 0

		click 'New TestRequestmap'
		assertContentContains 'Create TestRequestmap'

		form {
			url = '/secure/**'
			configAttribute = 'ROLE_ADMIN'
			clickButton 'Create'
		}

		assertContentContains 'Show TestRequestmap'
		click 'TestRequestmap List'

		verifyListSize 1
	}

	private void checkSecurePageNotVisibleWithRequestmap() {
		get '/secure'
		assertContentContains 'Please Login'
	}

	private void loginAndCheckAllAllowed() {
		// login
		get '/login/auth'
		assertContentContains 'Please Login'

		form {
			j_username = 'new_user'
			j_password = 'p4ssw0rd'
			_spring_security_remember_me = true
			clickButton 'Login'
		}

		// Check that with a requestmap, /secure is accessible after login
		get '/secure'
		assertContentContains 'SECURE'
	}
}
