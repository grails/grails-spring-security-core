package com.testapp

import grails.gorm.transactions.Transactional
import org.springframework.dao.DataIntegrityViolationException
import org.springframework.security.access.annotation.Secured

@Transactional
@Secured('permitAll')
class TestRequestmapController {

	def springSecurityService

	static defaultAction = 'list'

	def list() {
		params.max = Math.min(params.max ? params.int('max') : 10, 100)
		[testRequestmaps: TestRequestmap.list(params), testRequestmapCount: TestRequestmap.count()]
	}

	def create(TestRequestmap testRequestmap) {
		[testRequestmap: testRequestmap]
	}

	def save(TestRequestmap testRequestmap) {
		if (!testRequestmap.save(flush: true)) {
			render view: 'create', model: [testRequestmap: testRequestmap]
			return
		}

		springSecurityService.clearCachedRequestmaps()
		flash.message = "TestRequestmap $testRequestmap.id created"
		redirect action: 'show', id: testRequestmap.id
	}

	def show(TestRequestmap testRequestmap, Long id) {
		if (!testRequestmap) {
			flash.message = "TestRequestmap not found with id $id"
			redirect action: 'list'
			return
		}

		[testRequestmap: testRequestmap]
	}

	def edit(TestRequestmap testRequestmap, Long id) {
		if (!testRequestmap) {
			flash.message = "TestRequestmap not found with id $id"
			redirect action: 'list'
			return
		}

		[testRequestmap: testRequestmap]
	}

	def update(TestRequestmap testRequestmap, Long id, Long version) {
		if (!testRequestmap) {
			flash.message = "TestRequestmap not found with id $id"
			redirect action: 'list'
			return
		}

		if (version != null && testRequestmap.version > version) {
			testRequestmap.errors.rejectValue 'version', 'default.optimistic.locking.failure',
				'Another user has updated this TestRequestmap while you were editing'
			render view: 'edit', model: [testRequestmap: testRequestmap]
			return
		}

		testRequestmap.properties = params
		if (!testRequestmap.hasErrors() && testRequestmap.save(flush: true)) {
			springSecurityService.clearCachedRequestmaps()
			flash.message = "TestRequestmap $testRequestmap.id updated"
			redirect action: 'show', id: testRequestmap.id
		}
		else {
			render view: 'edit', model: [testRequestmap: testRequestmap]
		}
	}

	def delete(TestRequestmap testRequestmap, Long id) {
		if (!testRequestmap) {
			flash.message = "TestRequestmap not found with id $id"
			redirect action: 'list'
			return
		}

		try {
			testRequestmap.delete(flush: true)
			springSecurityService.clearCachedRequestmaps()
			flash.message = "TestRequestmap $id deleted"
			redirect action: 'list'
		}
		catch (DataIntegrityViolationException e) {
			flash.message = "TestRequestmap $id could not be deleted"
			redirect action: 'show', id: id
		}
	}
}
