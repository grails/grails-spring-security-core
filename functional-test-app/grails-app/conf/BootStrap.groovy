
class BootStrap {
	def testDataService

	def init = { servletContext ->
		testDataService.enterInitialData()
	}
}
