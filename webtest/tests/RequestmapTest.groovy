class RequestmapTest extends AbstractSecurityWebTest {

	void testRequestmapListNewDelete() {
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

		get '/testRequestmap/edit/1'
		assertContentContains 'Edit TestRequestmap'
		clickButton 'Update'
		assertContentContains 'Show TestRequestmap'
		click 'TestRequestmap List'

		verifyListSize 1

		get '/testRequestmap/show/1'
		clickButton 'Delete'

		verifyXPath "//div[@class='message']", '.*TestRequestmap.*deleted.*', true

		verifyListSize 0
	}
}
