class RequestmapSecurityTest extends AbstractSecurityWebTest {

	void testRequestmapSecurity() {

		checkSecurePageVisibleWithoutRequestmap()

		createRoles()
		createUsers()

		createRequestMaps()
		checkSecurePageNotVisibleWithRequestmap()

		loginAndCheckAllowed()
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
			authority = 'ROLE_USER'
			clickButton 'Create'
		}

		assertContentContains 'Show TestRole'
		click 'TestRole List'

		verifyListSize 2
	}

	private void createUsers() {
		get '/testUser'
		assertContentContains'Home'

		verifyListSize 0

		click 'New TestUser'
		assertContentContains 'Create TestUser'

		form {
			username = 'admin1'
			password = 'p4ssw0rd'
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
			username = 'user1'
			password = 'p4ssw0rd'
			enabled = true
			ROLE_USER = true
			clickButton 'Create'
		}

		assertContentContains 'Show TestUser'
		click 'TestUser List'

		verifyListSize 2
	}

	private void checkSecurePageVisibleWithoutRequestmap() {
		get '/secure'
		assertContentContains 'SECURE'

		get '/secure/expression'
		assertContentContains 'OK'
	}

	private void createRequestMaps() {
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

		click 'New TestRequestmap'
		assertContentContains 'Create TestRequestmap'

		form {
			url = '/secure/expression'
			configAttribute = "authentication.name == 'user1'"
			clickButton 'Create'
		}

		assertContentContains 'Show TestRequestmap'
		click 'TestRequestmap List'

		verifyListSize 2
	}

	private void checkSecurePageNotVisibleWithRequestmap() {
		get '/secure'
		assertContentContains 'Please Login'

		get '/secure/expression'
		assertContentContains 'Please Login'
	}

	private void loginAndCheckAllowed() {
		get '/logout'
		assertContentContains 'Welcome to Grails'

		// login as admin1
		get '/login/auth'
		assertContentContains 'Please Login'

		form {
			j_username = 'admin1'
			j_password = 'p4ssw0rd'
			_spring_security_remember_me = true
			clickButton 'Login'
		}

		// Check that with a requestmap, /secure is accessible after login
		get '/secure'
		assertContentContains 'SECURE'

		// but 'expression' requires user1
		get '/secure/expression'
		assertContentContains "Sorry, you're not authorized to view this page."

		// login as user1
		get '/logout'
		assertContentContains 'Welcome to Grails'

		get '/login/auth'
		assertContentContains 'Please Login'

		form {
			j_username = 'user1'
			j_password = 'p4ssw0rd'
			_spring_security_remember_me = true
			clickButton 'Login'
		}

		get '/secure'
		assertContentContains "Sorry, you're not authorized to view this page."

		get '/secure/expression'
		assertContentContains 'OK'
	}
}
