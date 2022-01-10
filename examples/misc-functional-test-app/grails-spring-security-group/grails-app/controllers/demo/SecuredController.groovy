package demo

import grails.plugin.springsecurity.annotation.Secured
import groovy.transform.CompileStatic

@CompileStatic
class SecuredController {

    @Secured('ROLE_ADMIN')
    def index() {
        render 'you have ROLE_ADMIN'
    }
}