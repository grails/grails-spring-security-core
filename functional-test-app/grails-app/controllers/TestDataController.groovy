
class TestDataController {
	TestDataService testDataService

	def reset() {
		testDataService.returnToInitialState()
		render 'OK'
	}

	def addTestUsers() {
		testDataService.addTestUsers()
		render 'OK'
	}
}
