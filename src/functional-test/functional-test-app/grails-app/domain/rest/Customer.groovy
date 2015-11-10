package rest

import grails.rest.Resource

@Resource(superClass=CustomerBaseController, readOnly = true)
class Customer {

	String name
}
