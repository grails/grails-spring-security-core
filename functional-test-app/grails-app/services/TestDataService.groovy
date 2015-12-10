import com.testapp.TestRequestmap
import com.testapp.TestRole
import com.testapp.TestUser
import com.testapp.TestUserTestRole

import grails.plugin.springsecurity.SpringSecurityUtils
import groovy.sql.Sql
import rest.Book
import rest.Movie

class TestDataService {

	def dataSource
	def grailsApplication
	def objectDefinitionSource

	//	'/error', '/hack/**', and '/testData/**' are handled in TestRequestmapFilterInvocationDefinition
	private static final List<String> URIS_FOR_REQUESTMAPS = [
		'/', '/**/css/**', '/**/favicon.ico', '/**/images/**', '/**/js/**', '/assets/**', '/dbconsole',
		'/dbconsole/**', '/index', '/index.gsp', '/login', '/login/**', '/shutdown', '/taglibtest/**',
		'/testrequestmap', '/testrequestmap/**', '/testrole', '/testrole/**', '/testuser', '/testuser/**']

	void returnToInitialState() {
		truncateTablesAndRetry 3, false
		enterInitialData()
		objectDefinitionSource.reset()
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
		println "truncateTables: start"
		Sql sql
		boolean success = true
		try {
			sql = new Sql(dataSource)
			sql.rows('SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = SCHEMA()').each { row ->
				try {
					int rowCount = sql.executeUpdate('DELETE FROM ' + row.TABLE_NAME)
					if (rowCount) println "truncateTables: deleted $rowCount row(s) from $row.TABLE_NAME"
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
			println "truncateTables: end"
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

		if (SpringSecurityUtils.securityConfigType != 'Requestmap') {
			return
		}

		if (TestRequestmap.count()) {
			return
		}

		for (url in URIS_FOR_REQUESTMAPS) {
			save new TestRequestmap(url, 'permitAll')
		}

		assert URIS_FOR_REQUESTMAPS.size() == TestRequestmap.count()
	}

	void addTestUsers() {
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
