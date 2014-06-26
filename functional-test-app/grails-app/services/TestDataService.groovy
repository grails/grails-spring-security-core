import grails.plugin.springsecurity.SpringSecurityUtils
import groovy.sql.Sql;

class TestDataService {
	def grailsApplication
	def dataSource
	
	void returnToInitialState() {
		truncateTablesAndRetry(3, false)
		enterInitialData()
	}

	boolean truncateTablesAndRetry(int retryCount, boolean ignoreExceptions) {
		for(int i=0;i < retryCount;i++) {
			// foreign key constraints cause exceptions when deleting data in wrong order
			// just ignore them and re-try 3 times
			if(truncateTables(true)) {
				break
			}
		}
		truncateTables(ignoreExceptions) // make sure everything is deleted
	}
	
	boolean truncateTables(boolean ignoreExceptions = false) {
		Sql sql
		boolean success = true
		try {
			sql = new Sql(dataSource)
			sql.rows("SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = SCHEMA()").each { row ->
				try {
					sql.executeUpdate("DELETE FROM ${row.TABLE_NAME}".toString())
				} catch (Exception e) {
					success = false
					if(!ignoreExceptions) {
						throw e
					}
				}
			}
		} finally {
			sql?.close()
		}
		success
	}
	
	void enterInitialData() {
		if (SpringSecurityUtils.securityConfigType != 'Requestmap') {
			return
		}
		
		String requestMapClassName = SpringSecurityUtils.securityConfig.requestMap.className
		def Requestmap = grailsApplication.getClassForName(requestMapClassName)
		if (Requestmap.count()) {
			return
		}

		for (url in ['/', '/index', '/index.gsp', '/assets/**', '/**/js/**', '/**/css/**', '/**/images/**', '/**/favicon.ico',
						 '/login', '/login/**', '/logout', '/logout/**',
						 '/hack', '/hack/**', '/tagLibTest', '/tagLibTest/**',
						 '/testRequestmap', '/testRequestmap/**',
						 '/testUser', '/testUser/**', '/testRole', '/testRole/**', '/testData/**', '/dbconsole/**', '/dbconsole', '/assets/**']) {
			Requestmap.newInstance(url: url, configAttribute: 'permitAll').save(flush: true, failOnError: true)
		}

		assert 26 == Requestmap.count()
	}
}
