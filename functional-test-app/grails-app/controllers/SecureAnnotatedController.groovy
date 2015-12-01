import grails.plugin.springsecurity.annotation.Secured

class SecureAnnotatedController {

	@Secured('ROLE_ADMIN')
	def index() {
		render 'you have ROLE_ADMIN'
	}

	@Secured(['ROLE_ADMIN', 'ROLE_ADMIN2'])
	def adminEither() {
		render 'you have ROLE_ADMIN or ROLE_ADMIN2'
	}

	@Secured('ROLE_USER')
	def userAction() {
		render 'you have ROLE_USER'
	}

	@Secured("authentication.name == 'admin1'")
	def expression() {
		render 'expression: OK'
	}

	@Secured('ROLE_ADMIN')
	def indexMethod() {
		render 'you have ROLE_ADMIN - method'
	}

	@Secured(['ROLE_ADMIN', 'ROLE_ADMIN2'])
	def adminEitherMethod() {
		render 'you have ROLE_ADMIN or ROLE_ADMIN2 - method'
	}

	@Secured('ROLE_USER')
	def userActionMethod() {
		render 'you have ROLE_USER - method'
	}

	@Secured("authentication.name == 'admin1'")
	def expressionMethod() {
		render 'OK - method'
	}

	@Secured(closure = {
		assert request
		assert ctx
		authentication.name == 'admin1'
	})
	def closureMethod() {
		render 'OK - closureMethod'
	}
}
