import grails.plugins.springsecurity.Secured

class SecureAnnotatedController {

	@Secured(['ROLE_ADMIN'])
	def index = {
		render 'you have ROLE_ADMIN'
	}

	@Secured(['ROLE_ADMIN', 'ROLE_ADMIN2'])
	def adminEither = {
		render 'you have ROLE_ADMIN or ROLE_ADMIN2'
	}

	@Secured(['ROLE_USER'])
	def userAction = {
		render 'you have ROLE_USER'
	}

	@Secured(["authentication.name == 'admin1'"])
	def expression = {
		render 'OK'
	}
}
