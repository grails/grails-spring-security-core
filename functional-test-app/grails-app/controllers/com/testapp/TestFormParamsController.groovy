package com.testapp

import grails.plugin.springsecurity.annotation.Secured
import grails.validation.Validateable

/**
 * This controller is used to verify that form parameters on PUT and PATCH requests are available
 */
class TestFormParamsController {

    static allowedMethods = [
            permitAll  : ["PUT", "PATCH"],
            permitAdmin: ["PUT", "PATCH"]
    ]

    @Secured(['permitAll'])
    def permitAll(TestFormCommand cmd) {
        render "username: ${cmd.username}, password: ${cmd.password}"
    }

    @Secured(['ROLE_ADMIN'])
    def permitAdmin(TestFormCommand cmd) {
        render "username: ${cmd.username}, password: ${cmd.password}"
    }
}

class TestFormCommand implements Validateable {
    String username
    String password

    static constraints = {
        username(nullable: true)
        password(nullable: true)
    }
}