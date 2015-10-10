package rest

import grails.rest.Resource

@Resource(superClass=CustomerRestController, readOnly = true)
class Customer {

    String name

}
