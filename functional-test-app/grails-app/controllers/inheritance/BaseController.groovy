package inheritance

import grails.plugin.springsecurity.annotation.Secured

@Secured(["ROLE_USER"])
class BaseController {
	def index() {
		render 'BaseController'
	}

	@Secured(["ROLE_BASE"])
	def delete() {
		render 'DELETED'
	}

	def update() {
		render 'BaseController - UPDATED'
	}
}
