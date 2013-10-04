class RequestmapTest extends AbstractSecurityWebTest {

	void testRequestmapListNewDelete() {
		get '/testRequestmap/list?max=100'

		assertContentContains 'Home'

		verifyListSize 20

		click 'New TestRequestmap'
		assertContentContains 'Create TestRequestmap'

		form {
			url = '/secure/**'
			configAttribute = 'ROLE_ADMIN'
			clickButton 'Create'
		}

		assertContentContains 'Show TestRequestmap'
		get '/testRequestmap/list?max=100'

		verifyListSize 21

		get '/testRequestmap/edit/21'
		assertContentContains 'Edit TestRequestmap'
		clickButton 'Update'
		assertContentContains 'Show TestRequestmap'
		get '/testRequestmap/list?max=100'

		verifyListSize 21

		get '/testRequestmap/show/21'
		clickButton 'Delete'

		verifyXPath "//div[@class='message']", '.*TestRequestmap.*deleted.*', true

		get '/testRequestmap/list?max=100'
		verifyListSize 20
	}
}
