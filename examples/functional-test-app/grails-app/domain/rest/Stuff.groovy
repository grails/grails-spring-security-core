package rest

import grails.plugin.springsecurity.annotation.Secured
import grails.rest.Resource

@Resource(uri = '/stuffs')
@Secured('ROLE_ADMIN')
class Stuff {
	String name
}
