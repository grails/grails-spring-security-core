class UserTest extends AbstractSecurityWebTest {

	void testUserListNewDelete() {
		get '/testUser'
		assertContentContains 'Home'

		verifyListSize 0

		click 'New TestUser'
		assertContentContains 'Create TestUser'

		form {
			username = 'new_user'
			password = 'p4ssw0rd'
			enabled = true
		}
		clickButton 'Create'

		assertContentContains 'Show TestUser'
		click 'TestUser List'

		verifyListSize 1

		get '/testUser/edit/1'
		assertContentContains 'Edit TestUser'

		form {
			username = 'new_user2'
			password = 'p4ssw0rd2'
			enabled = false
		}
		clickButton 'Update'

		assertContentContains 'Show TestUser'
		click 'TestUser List'

		verifyListSize 1

		get '/testUser/show/1'
		clickButton 'Delete'
		verifyXPath "//div[@class='message']", ".*TestUser.*deleted.*", true

		verifyListSize 0
	}
}
