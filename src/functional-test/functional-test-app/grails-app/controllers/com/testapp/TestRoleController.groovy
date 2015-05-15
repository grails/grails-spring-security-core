package com.testapp

import org.springframework.dao.DataIntegrityViolationException
import org.springframework.security.access.annotation.Secured

@Secured('permitAll')
class TestRoleController {

	def springSecurityService

	static defaultAction = 'list'

	def list() {
		params.max = Math.min(params.max ? params.int('max') : 10, 100)
		[testRoleInstanceList: TestRole.list(params), testRoleInstanceTotal: TestRole.count()]
	}

	def create() {
		[testRoleInstance: new TestRole(params)]
	}

	def save() {
		def testRoleInstance = new TestRole(params)
		if (!testRoleInstance.save(flush: true)) {
			render view: 'create', model: [testRoleInstance: testRoleInstance]
			return
		}

		flash.message = "${message(code: 'default.created.message', args: [message(code: 'testRole.label', default: 'TestRole'), testRoleInstance.id])}"
		redirect action: 'show', id: testRoleInstance.id
	}

	def show() {
		def testRoleInstance = TestRole.get(params.id)
		if (!testRoleInstance) {
			flash.message = "${message(code: 'default.not.found.message', args: [message(code: 'testRole.label', default: 'TestRole'), params.id])}"
			redirect action: 'list'
			return
		}

		[testRoleInstance: testRoleInstance]
	}

	def edit() {
		def testRoleInstance = TestRole.get(params.id)
		if (!testRoleInstance) {
			flash.message = "${message(code: 'default.not.found.message', args: [message(code: 'testRole.label', default: 'TestRole'), params.id])}"
			redirect action: 'list'
			return
		}

		[testRoleInstance: testRoleInstance]
	}

	def update() {
		def testRoleInstance = TestRole.get(params.id)
		if (!testRoleInstance) {
			flash.message = "${message(code: 'default.not.found.message', args: [message(code: 'testRole.label', default: 'TestRole'), params.id])}"
			redirect action: 'list'
			return
		}

		if (params.version) {
			def version = params.version.toLong()
			if (testRoleInstance.version > version) {
				testRoleInstance.errors.rejectValue('version', 'default.optimistic.locking.failure',
						[message(code: 'testRole.label', default: 'TestRole')] as Object[],
						'Another user has updated this TestRole while you were editing')
				render(view: 'edit', model: [testRoleInstance: testRoleInstance])
				return
			}
		}

		if (!springSecurityService.updateRole(testRoleInstance, params)) {
			render view: 'edit', model: [testRoleInstance: testRoleInstance]
			return
		}

		flash.message = "${message(code: 'default.updated.message', args: [message(code: 'testRole.label', default: 'TestRole'), testRoleInstance.id])}"
		redirect action: 'show', id: testRoleInstance.id
	}

	def delete() {
		def testRoleInstance = TestRole.get(params.id)
		if (!testRoleInstance) {
			flash.message = "${message(code: 'default.not.found.message', args: [message(code: 'testRole.label', default: 'TestRole'), params.id])}"
			redirect action: 'list'
			return
		}

		try {
			springSecurityService.deleteRole testRoleInstance
			flash.message = "${message(code: 'default.deleted.message', args: [message(code: 'testRole.label', default: 'TestRole'), params.id])}"
			redirect action: 'list'
		}
		catch (DataIntegrityViolationException e) {
			flash.message = "${message(code: 'default.not.deleted.message', args: [message(code: 'testRole.label', default: 'TestRole'), params.id])}"
			redirect action: 'show', id: params.id
		}
	}
}
