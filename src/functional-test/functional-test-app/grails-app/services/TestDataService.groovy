import com.testapp.TestRequestmap
import com.testapp.TestRole
import com.testapp.TestUser
import com.testapp.TestUserTestRole

import grails.plugin.springsecurity.SpringSecurityUtils
import groovy.sql.Sql
import rest.Book
import rest.Movie

class TestDataService {
	def grailsApplication
	def dataSource

	void returnToInitialState() {
		truncateTablesAndRetry 3, false
		enterInitialData()
	}

	boolean truncateTablesAndRetry(int retryCount, boolean ignoreExceptions) {
		for (int i = 0; i < retryCount; i++) {
			// foreign key constraints cause exceptions when deleting data in wrong order
			// just ignore them and re-try 3 times
			if (truncateTables(true)) {
				break
			}
		}
		truncateTables ignoreExceptions // make sure everything is deleted
	}

	boolean truncateTables(boolean ignoreExceptions = false) {
		Sql sql
		boolean success = true
		try {
			sql = new Sql(dataSource)
			sql.rows('SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = SCHEMA()').each { row ->
				try {
					sql.executeUpdate 'DELETE FROM ' + row.TABLE_NAME
				}
				catch (e) {
					success = false
					if (!ignoreExceptions) {
						throw e
					}
				}
			}
		}
		finally {
			sql?.close()
		}
		success
	}

	void enterInitialData() {
		Book.findOrSaveByTitle 'TestBook'
		Movie.findOrSaveByTitle 'TestMovie'

		if (System.getProperty('add_test_users')) {
			addTestUsers()
		}

		if (SpringSecurityUtils.securityConfigType == 'Requestmap') {
			if (TestRequestmap.count()) {
				return
			}

			for (url in ['/', '/error', '/index', '/index.gsp', '/shutdown', '/assets/**', '/**/js/**', '/**/css/**', '/**/images/**', '/**/favicon.ico',
			             '/login', '/login/**', '/logout', '/logout/**',
			             '/hack', '/hack/**', '/tagLibTest', '/tagLibTest/**',
			             '/testRequestmap', '/testRequestmap/**',
			             '/testUser', '/testUser/**', '/testRole', '/testRole/**', '/testData/**', '/dbconsole/**', '/dbconsole', '/assets/**']) {
				save new TestRequestmap(url, 'permitAll')
			}

			assert 26 == TestRequestmap.count()
		}
	}

	def addTestUsers() {
		println 'Adding test users'
		addTestUser 'admin',                     'ROLE_ADMIN'
		addTestUser 'testuser',                  'ROLE_USER', 'ROLE_BASE', 'ROLE_EXTENDED'
		addTestUser 'testuser_books',            'ROLE_BOOKS'
		addTestUser 'testuser_movies',           'ROLE_MOVIES'
		addTestUser 'testuser_books_and_movies', 'ROLE_BOOKS', 'ROLE_MOVIES'
	}

	TestUser addTestUser(String username, String... roles) {
		def testUser = save(new TestUser(username, 'password'))
		roles.each { save new TestUserTestRole(testUser: testUser, testRole: TestRole.findOrSaveByAuthority(it)) }
		testUser
	}

	private save(o) {
		o.save(failOnError: true)
	}
}
