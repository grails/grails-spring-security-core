class RoleTest extends AbstractSecurityWebTest {

	void testRoleListNewDelete() {

		get '/testRole'
		assertContentContains 'Home'

		verifyListSize 0

		click 'New TestRole'
		assertContentContains 'Create TestRole'

		form {
			authority = 'test'
		}
		clickButton 'Create'

		assertContentContains 'Show TestRole'
		click 'TestRole List'

		verifyListSize 1

		get '/testRole/show/1'
		clickButton 'Edit'
		assertContentContains 'Edit TestRole'

		form {
			authority = 'test_new'
		}
		clickButton 'Update'

		assertContentContains 'Show TestRole'
		click 'TestRole List'

		verifyListSize 1

		get '/testRole/show/1'
		clickButton 'Delete'
		verifyXPath "//div[@class='message']", ".*TestRole.*deleted.*", true

		verifyListSize 0
	}
}
