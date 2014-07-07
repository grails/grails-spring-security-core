package inheritance

import grails.plugin.springsecurity.annotation.Secured

class ExtendedController extends BaseController {
	def index() {
		render 'ExtendedController'
	}
	
	@Secured(["ROLE_EXTENDED"])
	def update() {
		render 'ExtendedController - UPDATED'
	}
}
