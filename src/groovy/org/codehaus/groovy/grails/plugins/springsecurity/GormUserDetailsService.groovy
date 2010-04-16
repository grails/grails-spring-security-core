/* Copyright 2006-2010 the original author or authors.
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
package org.codehaus.groovy.grails.plugins.springsecurity

import org.apache.log4j.Logger
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.GrantedAuthorityImpl
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.transaction.PlatformTransactionManager
import org.springframework.transaction.TransactionStatus
import org.springframework.transaction.support.TransactionCallback
import org.springframework.transaction.support.TransactionTemplate

/**
 * Default implementation of <code>GrailsUserDetailsService</code> that uses domain classes to load users and roles.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class GormUserDetailsService implements GrailsUserDetailsService {

	private Logger _log = Logger.getLogger(getClass())

	/**
	 * Some Spring Security classes (e.g. RoleHierarchyVoter) expect at least one role, so
	 * we give a user with no granted roles this one which gets past that restriction but
	 * doesn't grant anything.
	 */
	static final List NO_ROLES = [new GrantedAuthorityImpl(SpringSecurityUtils.NO_ROLE)]

	/** Dependency injection for Hibernate session factory. */
	def sessionFactory

	/** Dependency injection for Hibernate transaction manager. */
	PlatformTransactionManager transactionManager

	/**
	 * {@inheritDoc}
	 * @see org.codehaus.groovy.grails.plugins.springsecurity.GrailsUserDetailsService#loadUserByUsername(
	 * 	java.lang.String, boolean)
	 */
	UserDetails loadUserByUsername(String username, boolean loadRoles) throws UsernameNotFoundException  {
		def callback = { TransactionStatus status -> loadUserFromSession(username, sessionFactory.currentSession, loadRoles) }
		new TransactionTemplate(transactionManager).execute(callback as TransactionCallback)
	}

	/**
	 * {@inheritDoc}
	 * @see org.springframework.security.core.userdetails.UserDetailsService#loadUserByUsername(java.lang.String)
	 */
	UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		loadUserByUsername username, true
	}

	protected UserDetails loadUserFromSession(String username, session, boolean loadRoles) {
		def user = loadUser(username, session)
		Collection<GrantedAuthority> authorities = loadAuthorities(user, username, loadRoles)
		createUserDetails user, authorities
	}

	protected loadUser(String username, session) {
		String userDomainClassName = ReflectionUtils.getConfigProperty('userLookup.userDomainClassName')
		String usernamePropertyName = ReflectionUtils.getConfigProperty('userLookup.usernamePropertyName')

		List<?> users = session.createQuery(
				"FROM $userDomainClassName WHERE $usernamePropertyName = :username")
				.setString('username', username)
				.list()

		if (!users) {
			log.warn "User not found: $username"
			throw new UsernameNotFoundException('User not found', username)
		}

		users[0]
	}

	protected Collection<GrantedAuthority> loadAuthorities(user, String username, boolean loadRoles) {
		if (!loadRoles) {
			return []
		}

		String authoritiesPropertyName = ReflectionUtils.getConfigProperty('userLookup.authoritiesPropertyName')
		String authorityPropertyName = ReflectionUtils.getConfigProperty('authority.nameField')

		Collection<?> userAuthorities = user."$authoritiesPropertyName"
		def authorities = userAuthorities.collect { new GrantedAuthorityImpl(it."$authorityPropertyName") }
		authorities ?: NO_ROLES
	}

	protected UserDetails createUserDetails(user, Collection<GrantedAuthority> authorities) {

		String usernamePropertyName = ReflectionUtils.getConfigProperty('userLookup.usernamePropertyName')
		String enabledPropertyName = ReflectionUtils.getConfigProperty('userLookup.enabledPropertyName')
		String passwordPropertyName = ReflectionUtils.getConfigProperty('userLookup.passwordPropertyName')

		String username = user."$usernamePropertyName"
		String password = user."$passwordPropertyName"
		boolean enabled = user."$enabledPropertyName"

		new User(username, password, enabled, enabled, enabled, enabled, authorities)
	}

	protected Logger getLog() { _log }
}
