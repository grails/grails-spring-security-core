import grails.plugins.springsecurity.Secured

@Secured(['ROLE_ADMIN'])
class SecureClassAnnotatedController {

	def index = {
		render 'index: you have ROLE_ADMIN'
	}

	def otherAction = {
		render 'otherAction: you have ROLE_ADMIN'
	}

	@Secured(['ROLE_ADMIN2'])
	def admin2 = {
		render 'admin2: you have ROLE_ADMIN2'
	}
}
