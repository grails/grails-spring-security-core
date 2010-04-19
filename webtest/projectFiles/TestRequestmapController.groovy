package com.testapp

import org.springframework.dao.DataIntegrityViolationException

class TestRequestmapController {

	static allowedMethods = [save: 'POST', update: 'POST', delete: 'POST']

	static defaultAction = 'list'

	def springSecurityService

	def list = {
		params.max = Math.min(params.max ? params.int('max') : 10, 100)
		[testRequestmapInstanceList: TestRequestmap.list(params),
		 testRequestmapInstanceTotal: TestRequestmap.count()]
	}

	def create = {
		[testRequestmapInstance: new TestRequestmap(params)]
	}

	def save = {
		def testRequestmapInstance = new TestRequestmap(params)
		if (!testRequestmapInstance.save(flush: true)) {
			render view: 'create', model: [testRequestmapInstance: testRequestmapInstance]
			return
		}

		springSecurityService.clearCachedRequestmaps()
		flash.message = "${message(code: 'default.created.message', args: [message(code: 'testRequestmap.label', default: 'TestRequestmap'), testRequestmapInstance.id])}"
		redirect action: show, id: testRequestmapInstance.id
	}

	def show = {
		def testRequestmapInstance = TestRequestmap.get(params.id)
		if (!testRequestmapInstance) {
			flash.message = "${message(code: 'default.not.found.message', args: [message(code: 'testRequestmap.label', default: 'TestRequestmap'), params.id])}"
			redirect action: list
			return
		}

		[testRequestmapInstance: testRequestmapInstance]
	}

	def edit = {
		def testRequestmapInstance = TestRequestmap.get(params.id)
		if (!testRequestmapInstance) {
			flash.message = "${message(code: 'default.not.found.message', args: [message(code: 'testRequestmap.label', default: 'TestRequestmap'), params.id])}"
			redirect action: list
			return
		}

		[testRequestmapInstance: testRequestmapInstance]
	}

	def update = {
		def testRequestmapInstance = TestRequestmap.get(params.id)
		if (!testRequestmapInstance) {
         flash.message = "${message(code: 'default.not.found.message', args: [message(code: 'testRequestmap.label', default: 'TestRequestmap'), params.id])}"
         redirect action: list
         return
		}

		if (params.version) {
			def version = params.version.toLong()
			if (testRequestmapInstance.version > version) {
				testRequestmapInstance.errors.rejectValue('version', 'default.optimistic.locking.failure',
						[message(code: 'testRequestmap.label', default: 'TestRequestmap')] as Object[],
						'Another user has updated this TestRequestmap while you were editing')
				render view: 'edit', model: [testRequestmapInstance: testRequestmapInstance]
				return
			}
		}

		testRequestmapInstance.properties = params
		if (!testRequestmapInstance.hasErrors() && testRequestmapInstance.save(flush: true)) {
			springSecurityService.clearCachedRequestmaps()
			flash.message = "${message(code: 'default.updated.message', args: [message(code: 'testRequestmap.label', default: 'TestRequestmap'), testRequestmapInstance.id])}"
			redirect action: show, id: testRequestmapInstance.id
		}
		else {
			render view: 'edit', model: [testRequestmapInstance: testRequestmapInstance]
		}
	}

	def delete = {
		def testRequestmapInstance = TestRequestmap.get(params.id)
		if (!testRequestmapInstance) {
			flash.message = "${message(code: 'default.not.found.message', args: [message(code: 'testRequestmap.label', default: 'TestRequestmap'), params.id])}"
			redirect action: list
			return
		}

		try {
			testRequestmapInstance.delete(flush: true)
			springSecurityService.clearCachedRequestmaps()
			flash.message = "${message(code: 'default.deleted.message', args: [message(code: 'testRequestmap.label', default: 'TestRequestmap'), params.id])}"
			redirect action: list
		}
		catch (DataIntegrityViolationException e) {
			flash.message = "${message(code: 'default.not.deleted.message', args: [message(code: 'testRequestmap.label', default: 'TestRequestmap'), params.id])}"
			redirect action: show, id: params.id
		}
	}
}
