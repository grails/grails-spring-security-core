package com.testapp

import groovy.transform.EqualsAndHashCode
import groovy.transform.ToString

@EqualsAndHashCode(includes='username')
@ToString(includes='username', includeNames=true, includePackage=false)
class TestUser implements Serializable {
	private static final long serialVersionUID = 1

	transient springSecurityService

	String username
	String password
	boolean enabled = true
	boolean accountExpired
	boolean accountLocked
	boolean passwordExpired

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
		password = springSecurityService?.passwordEncoder ? springSecurityService.encodePassword(password, salt()) : password
	}

	def salt() {
		if ( !springSecurityService ) {
			return null
		}
		def algorithm = springSecurityService.grailsApplication.config.grails.plugin.springsecurity.password.algorithm
		if ( algorithm == 'bcrypt' || algorithm == 'pbkdf2' ) {
			return null
		}

		def reflectionSaltProperty = springSecurityService.grailsApplication.config.grails.plugin.springsecurity.dao.reflectionSaltSourceProperty
		if ( reflectionSaltProperty ) {
			return getProperty(reflectionSaltProperty)
		}
		null
	}

	static transients = ['springSecurityService']

	static constraints = {
		username blank: false, unique: true
		password blank: false, password: true
	}
}
