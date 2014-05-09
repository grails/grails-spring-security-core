/* Copyright 2006-2014 SpringSource.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package grails.plugin.springsecurity

import grails.plugin.springsecurity.web.authentication.rememberme.GormPersistentTokenRepository
import groovy.sql.Sql

import java.text.SimpleDateFormat

import org.springframework.security.web.authentication.rememberme.PersistentRememberMeToken

import test.TestPersistentLogin
import grails.test.mixin.integration.IntegrationTestMixin
import grails.test.mixin.*
import org.junit.*
import static org.junit.Assert.*

/**
 * Integration tests for <code>GormPersistentTokenRepository</code>, based on the tests
 * for <code>JdbcTokenRepositoryImpl</code>.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
 @TestMixin(IntegrationTestMixin)
class GormPersistentTokenRepositoryTests {

	private static final String DATE_FORMAT = 'yyyy-MM-dd HH:mm:ss'
	private static final Date DATE = new SimpleDateFormat(DATE_FORMAT).parse(
			'2007-10-09 18:19:25')

	private GormPersistentTokenRepository repo = new GormPersistentTokenRepository()
	private Sql sql

	def dataSource
	def grailsApplication
	def sessionFactory

	// can't use sql to verify results with regular transaction-based tests
	static transactional = false

	@Before
	void setUp() {		
		sql = new Sql(dataSource)
		repo.grailsApplication = grailsApplication
	}

	@After
	void tearDown() {
		sessionFactory.currentSession.clear()
		sql.executeUpdate 'delete from persistent_logins'
		assertEquals 0, TestPersistentLogin.count()
	}

	@Test
	void testCreateNewTokenInsertsCorrectData() {
		Date currentDate = new Date()
		def token = new PersistentRememberMeToken('joeuser', 'joesseries', 'atoken', currentDate)
		repo.createNewToken token

		assertEquals 1, TestPersistentLogin.count()

		def row = sql.firstRow('select * from persistent_logins')

		assertEquals currentDate.time, row.last_used.time
		assertEquals 'joeuser', row.username
		assertEquals 'joesseries', row.series
		assertEquals 'atoken', row.token
	}

	void testRetrievingTokenReturnsCorrectData() {

		insertToken 'joesseries', 'joeuser', 'atoken', DATE

		PersistentRememberMeToken token = repo.getTokenForSeries('joesseries')

		assertEquals 'joeuser', token.username
		assertEquals 'joesseries', token.series
		assertEquals 'atoken', token.tokenValue
		assertEquals DATE.time, token.date.time
	}

	void testRemovingUserTokensDeletesData() {
		insertToken 'joesseries2', 'joeuser', 'atoken2', DATE
		insertToken 'joesseries', 'joeuser', 'atoken', DATE

		repo.removeUserTokens 'joeuser'

		assertEquals 0,
			sql.firstRow("select count(*) from persistent_logins where username='joeuser'")[0]
	}

	void testUpdatingTokenModifiesTokenValueAndLastUsed() {
		Date date = new Date(System.currentTimeMillis() - 1)
		insertToken 'joesseries', 'joeuser', 'atoken', date
		repo.updateToken 'joesseries', 'newtoken', new Date()

		def row = sql.firstRow("select * from persistent_logins where series='joesseries'")

		assertEquals 'joeuser', row.username
		assertEquals 'joesseries', row.series
		assertEquals 'newtoken', row.token
		Date lastUsed = row.last_used
		assertTrue lastUsed.time > date.time
	}

	private void insertToken(String series, String username, String token, Date lastUsed) {
		String formattedDate = new SimpleDateFormat(DATE_FORMAT).format(lastUsed)
		sql.execute "insert into persistent_logins (series, username, token, last_used) " +
		             "values ('$series', '$username', '$token', '$formattedDate')"
	}
}
