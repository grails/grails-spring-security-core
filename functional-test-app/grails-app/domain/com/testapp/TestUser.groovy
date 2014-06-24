package com.testapp

class TestUser {

	transient springSecurityService

	String username
	String password
	boolean enabled = true
	boolean accountExpired
	boolean accountLocked
	boolean passwordExpired

	static transients = ['springSecurityService']

	static constraints = {
		username blank: false, unique: true
		password blank: false
	}

	static mapping = {
		password column: '`password`'
	}

	Set<TestRole> getAuthorities() {
		TestUserTestRole.findAllByTestUser(this).collect { it.testRole } as Set
	}

	def beforeInsert() {
		encodePassword()
	}

	def beforeUpdate() {
		if (isDirty('password')) {
			encodePassword()
		}
	}

	protected void encodePassword() {
		password = springSecurityService.encodePassword(password, springSecurityService.grailsApplication.config.grails.plugin.springsecurity.dao.reflectionSaltSourceProperty ? username : null)
	}
}

