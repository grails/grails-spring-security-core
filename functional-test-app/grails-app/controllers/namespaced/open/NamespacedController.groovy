package namespaced.open

import grails.plugin.springsecurity.annotation.Secured

@Secured('permitAll')
class NamespacedController {

	static namespace = 'open'

	def index() {
		render 'open'
	}
}
