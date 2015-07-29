package com.testapp

class TestUser implements Serializable {

	private static final long serialVersionUID = 1

	transient springSecurityService

	String username
	String password
	boolean enabled = true
	boolean accountExpired
	boolean accountLocked
	boolean passwordExpired

	TestUser(String username, String password) {
		this()
		this.username = username
		this.password = password
	}

	@Override
	int hashCode() {
		username?.hashCode() ?: 0
	}

	@Override
	boolean equals(other) {
		is(other) || (other instanceof TestUser && other.username == username)
	}

	@Override
	String toString() {
		username
	}

	static transients = ['springSecurityService']

	static constraints = {
		username blank: false, unique: true
		password blank: false
	}

	Set<TestRole> getAuthorities() {
		TestUserTestRole.findAllByTestUser(this)*.testRole
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
