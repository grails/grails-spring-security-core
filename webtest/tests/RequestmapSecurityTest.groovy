class RequestmapSecurityTest extends AbstractSecurityWebTest {

	void testRequestmapSecurity() {

		checkSecurePageNotVisibleWithoutRequestmap()

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

	private void checkSecurePageNotVisibleWithoutRequestmap() {
		get '/secure'
		assertContentContains 'was denied as public invocations are not allowed via this interceptor'

		get '/secure/expression'
		assertContentContains 'was denied as public invocations are not allowed via this interceptor'
	}

	private void createRequestMaps() {
		get '/testRequestmap/list?max=100'
		assertContentContains 'Home'
		verifyListSize 20 // initial 20 from BootStrap

		click 'New TestRequestmap'
		assertContentContains 'Create TestRequestmap'

		form {
			url = '/secure'
			configAttribute = 'ROLE_ADMIN'
			clickButton 'Create'
		}

		assertContentContains 'Show TestRequestmap'

		get '/testRequestmap/list?max=100'
		verifyListSize 21

		click 'New TestRequestmap'
		assertContentContains 'Create TestRequestmap'

		form {
			url = '/secure/**'
			configAttribute = 'ROLE_ADMIN'
			clickButton 'Create'
		}

		assertContentContains 'Show TestRequestmap'

		get '/testRequestmap/list?max=100'
		verifyListSize 22

		click 'New TestRequestmap'
		assertContentContains 'Create TestRequestmap'

		form {
			url = '/secure/expression'
			configAttribute = "authentication.name == 'user1'"
			clickButton 'Create'
		}

		assertContentContains 'Show TestRequestmap'

		get '/testRequestmap/list?max=100'
		verifyListSize 23
	}

	private void checkSecurePageNotVisibleWithRequestmap() {
		get '/secure'
		assertContentContains 'Please Login'

		get '/secure/expression'
		assertContentContains 'Please Login'

		get '/secure/index.xml'
		assertContentContains 'Please Login'

		get '/secure/index;jsessionid=5514B068198CC7DBF372713326E14C12'
		assertContentContains 'Please Login'
	}

	private void loginAndCheckAllowed() {
		logout()
		assertContentContains 'Welcome to Grails'

		login 'admin1', 'p4ssw0rd'

		// Check that with a requestmap, /secure is accessible after login
		get '/secure'
		assertContentContains 'SECURE'

		// but 'expression' requires user1
		get '/secure/expression'
		assertContentContains "Sorry, you're not authorized to view this page."

		logout()
		assertContentContains 'Welcome to Grails'

		login 'user1', 'p4ssw0rd'

		get '/secure'
		assertContentContains "Sorry, you're not authorized to view this page."

		get '/secure/expression'
		assertContentContains 'OK'
	}
}
