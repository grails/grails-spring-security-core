
class TestDataController {
	TestDataService testDataService
	
	def reset() {
		testDataService.returnToInitialState()
		render 'OK'
	}
}
