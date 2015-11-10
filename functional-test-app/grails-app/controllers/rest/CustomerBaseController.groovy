package rest

import grails.plugin.springsecurity.annotation.Secured
import grails.rest.RestfulController

class CustomerBaseController<Customer> extends RestfulController<Customer> {

	static responseFormats = ['json', 'xml']

	CustomerBaseController(Class<Customer> domainClass) {
		this(domainClass, false)
	}

	CustomerBaseController(Class<Customer> domainClass, boolean readOnly) {
		super(domainClass, readOnly)
	}

	@Override
	@Secured('ROLE_ADMIN')
	def index(Integer max) {
		super.index(max)
	}
}
