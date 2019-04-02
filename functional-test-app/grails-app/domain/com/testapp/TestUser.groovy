package com.testapp

import groovy.transform.EqualsAndHashCode
import groovy.transform.ToString
import grails.compiler.GrailsCompileStatic

@GrailsCompileStatic
@EqualsAndHashCode(includes='username')
@ToString(includes='username', includeNames=true, includePackage=false)
class TestUser implements Serializable {

    private static final long serialVersionUID = 1

    String username
    String password
    Boolean enabled = true
    Boolean accountExpired = false
    Boolean accountLocked = false
    Boolean passwordExpired = false

    Set<TestRole> getAuthorities() {
        (TestUserTestRole.findAllByTestUser(this) as List<TestUserTestRole>)*.testRole as Set<TestRole>
    }

    static constraints = {
        password nullable: false, blank: false, password: true
        username nullable: false, blank: false, unique: true
        accountExpired nullable: true
        accountLocked nullable: true
        passwordExpired nullable: true
    }

    static mapping = {
	    password column: '`password`'
        cache: false
    }
}
