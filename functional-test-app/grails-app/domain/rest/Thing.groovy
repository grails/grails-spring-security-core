package rest

import grails.plugin.springsecurity.annotation.Secured
import grails.rest.Resource

@Resource
@Secured(['ROLE_USER'])
class Thing {

    String name

    static constraints = {
    }
}
