/* Copyright 2006-2015 the original author or authors.
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

import java.text.SimpleDateFormat

import org.springframework.security.web.authentication.rememberme.PersistentRememberMeToken

import grails.plugin.springsecurity.web.authentication.rememberme.GormPersistentTokenRepository
import groovy.sql.Sql
import test.TestPersistentLogin

/**
 * Integration tests for <code>GormPersistentTokenRepository</code>, based on the tests
 * for <code>JdbcTokenRepositoryImpl</code>.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class GormPersistentTokenRepositorySpec extends AbstractIntegrationSpec {

	private static final String DATE_FORMAT = 'yyyy-MM-dd HH:mm:ss'
	private static final Date DATE = new SimpleDateFormat(DATE_FORMAT).parse('2007-10-09 18:19:25')

	private Sql sql

	GormPersistentTokenRepository tokenRepository
	def dataSource

	def setup() {
		sql = new Sql(dataSource)
	}

	void 'create new token inserts correct data'() {

		when:
		Date currentDate = new Date()
		def token = new PersistentRememberMeToken('joeuser', 'joesseries', 'atoken', currentDate)
		tokenRepository.createNewToken token
		flushAndClear()

		then:
		1 == TestPersistentLogin.count()

		when:
		def row = sql.firstRow('select last_used, series, token, username from persistent_login')

		then:
		row
		currentDate.time == row.last_used.time
		'joeuser' == row.username
		'joesseries' == row.series
		'atoken' == row.token
	}

	void 'retrieving token returns correct data'() {

		when:
		insertToken 'joesseries', 'joeuser', 'atoken', DATE

		PersistentRememberMeToken token = tokenRepository.getTokenForSeries('joesseries')

		then:
		'joeuser' == token.username
		'joesseries' == token.series
		'atoken' == token.tokenValue
		DATE.time == token.date.time
	}

	void 'removing user tokens deletes data'() {
		when:
		insertToken 'joesseries2', 'joeuser', 'atoken2', DATE
		insertToken 'joesseries', 'joeuser', 'atoken', DATE

		tokenRepository.removeUserTokens 'joeuser'

		then:
		0 == sql.firstRow('select count(series) from persistent_login where username=?', ['joeuser'])[0]
	}

	void 'updating token modifies token value and lastUsed'() {
		when:
		Date date = new Date(System.currentTimeMillis() - 1)
		insertToken 'joesseries', 'joeuser', 'atoken', date
		tokenRepository.updateToken 'joesseries', 'newtoken', new Date()
		flushAndClear()

		def row = sql.firstRow('select last_used, series, token, username from persistent_login where series=?', ['joesseries'])
		Date lastUsed = row.last_used

		then:
		'joeuser' == row.username
		'joesseries' == row.series
		'newtoken' == row.token
		lastUsed.time > date.time
	}

	private void insertToken(String series, String username, String token, Date lastUsed) {
		String formattedDate = lastUsed.format(DATE_FORMAT)
		sql.execute 'insert into persistent_login (last_used, series, token, username) values (?, ?, ?, ?)',
		            [formattedDate, series, token, username]
	}
}
