package com.testapp

import grails.plugin.springsecurity.annotation.Secured
import grails.validation.Validateable
import org.springframework.web.bind.annotation.PutMapping

/**
 * This controller is used to verify that parameters on PUT and PATCH requests are available
 */
@Secured(['permitAll'])
class TestFormParamsController {

    static allowedMethods = [
            index: ["PUT", "PATCH"]
    ]

    @PutMapping
    def index(TestFormCommand cmd) {
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