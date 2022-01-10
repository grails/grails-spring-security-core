import grails.plugin.springsecurity.annotation.Secured

class IndexAnnotatedController {

	@Secured('ROLE_ADMIN')
	def index() {
		render 'index action, principal: ' + principal
	}

	def show() {
		render 'show action, principal: ' + principal
	}
}
