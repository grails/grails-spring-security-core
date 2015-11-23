import grails.plugin.springsecurity.annotation.Secured

@Secured('permitAll')
class TestDataController {

	TestDataService testDataService

	def reset() {
		testDataService.returnToInitialState()
		render 'returnToInitialState: OK'
	}

	def addTestUsers() {
		testDataService.addTestUsers()
		render 'addTestUsers: OK'
	}
}
