package rest

import grails.plugin.springsecurity.annotation.Secured
import grails.rest.RestfulController

class  CustomerRestController<Customer> extends RestfulController<Customer> {

    static responseFormats = ['json', 'xml']

    CustomerRestController(Class<Customer> domainClass) {
        this(domainClass, false)
    }

    CustomerRestController(Class<Customer> domainClass, boolean readOnly) { super(domainClass, readOnly) }

    @Override
    @Secured(['ROLE_USER'])
    def index(Integer max){
        super.index(max)
    }

}
