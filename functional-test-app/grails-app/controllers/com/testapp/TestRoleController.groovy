package com.testapp

import grails.gorm.transactions.Transactional
import org.springframework.dao.DataIntegrityViolationException
import org.springframework.security.access.annotation.Secured

@Secured('permitAll')
class TestRoleController {

	def springSecurityService

	static defaultAction = 'list'

	def list() {
		params.max = Math.min(params.max ? params.int('max') : 10, 100)
		[testRoles: TestRole.list(params), testRoleCount: TestRole.count()]
	}

	def create(TestRole testRole) {
		[testRole: testRole]
	}

	@Transactional
	def save(TestRole testRole) {
		if (!testRole.save(flush: true)) {
			render view: 'create', model: [testRole: testRole]
			return
		}

		flash.message = "TestRole $testRole.id created"
		redirect action: 'show', id: testRole.id
	}

	def show(TestRole testRole, Long id) {
		if (!testRole) {
			flash.message = "TestRole not found with id $id"
			redirect action: 'list'
			return
		}

		[testRole: testRole]
	}

	def edit(TestRole testRole, Long id) {
		if (!testRole) {
			flash.message = "TestRole not found with id $id"
			redirect action: 'list'
			return
		}

		[testRole: testRole]
	}

	def update(TestRole testRole, Long id, Long version) {
		if (!testRole) {
			flash.message = "TestRole not found with id $id"
			redirect action: 'list'
			return
		}

		if (version != null && testRole.version > version) {
			testRole.errors.rejectValue 'version', 'default.optimistic.locking.failure',
				'Another user has updated this TestRole while you were editing'
			render(view: 'edit', model: [testRole: testRole])
			return
		}

		if (!springSecurityService.updateRole(testRole, params)) {
			render view: 'edit', model: [testRole: testRole]
			return
		}

		flash.message = "TestRole $testRole.id updated"
		redirect action: 'show', id: testRole.id
	}

	def delete(TestRole testRole, Long id) {
		if (!testRole) {
			flash.message = "TestRole not found with id $id"
			redirect action: 'list'
			return
		}

		try {
			springSecurityService.deleteRole testRole
			flash.message = "TestRole $id deleted"
			redirect action: 'list'
		}
		catch (DataIntegrityViolationException e) {
			flash.message = "TestRole $id could not be deleted"
			redirect action: 'show', id: id
		}
	}
}
