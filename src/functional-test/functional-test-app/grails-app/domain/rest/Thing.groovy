package rest

import grails.plugin.springsecurity.annotation.Secured
import grails.rest.Resource

@Resource
@Secured('ROLE_ADMIN')
class Thing {
	String name
}
