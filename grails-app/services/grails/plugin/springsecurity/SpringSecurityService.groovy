/* Copyright 2006-2013 SpringSource.
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

import javax.servlet.http.HttpServletRequest

import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder as SCH
import org.springframework.transaction.annotation.Transactional

/**
 * Utility methods.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class SpringSecurityService {

	/** dependency injection for authenticationTrustResolver */
	def authenticationTrustResolver

	/** dependency injection for grailsApplication */
	def grailsApplication

	/** dependency injection for the password encoder */
	def passwordEncoder

	/** dependency injection for {@link FilterInvocationSecurityMetadataSource} */
	def objectDefinitionSource

	/** dependency injection for userDetailsService */
	def userDetailsService

	/** dependency injection for userCache */
	def userCache

	/**
	 * Get the currently logged in user's principal. If not authenticated and the
	 * AnonymousAuthenticationFilter is active (true by default) then the anonymous
	 * user's name will be returned ('anonymousUser' unless overridden).
	 *
	 * @return the principal
	 */
	def getPrincipal() { getAuthentication()?.principal }

	/**
	 * Get the currently logged in user's <code>Authentication</code>. If not authenticated
	 * and the AnonymousAuthenticationFilter is active (true by default) then the anonymous
	 * user's auth will be returned (AnonymousAuthenticationToken with username 'anonymousUser'
	 * unless overridden).
	 *
	 * @return the authentication
	 */
	Authentication getAuthentication() { SCH.context?.authentication }

	/**
	 * Get the domain class instance associated with the current authentication.
	 * @return the user
	 */
	Object getCurrentUser() {
		if (!isLoggedIn()) {
			return null
		}

		String className = SpringSecurityUtils.securityConfig.userLookup.userDomainClassName
		String usernamePropName = SpringSecurityUtils.securityConfig.userLookup.usernamePropertyName
		grailsApplication.getClassForName(className).findWhere((usernamePropName): principal.username)
	}

	/**
	 * Encode the password using the configured PasswordEncoder.
	 */
	String encodePassword(String password, salt = null) {
		if ('bcrypt' == SpringSecurityUtils.securityConfig.password.algorithm || 'pbkdf2' == SpringSecurityUtils.securityConfig.password.algorithm) {
			salt = null
		}
		passwordEncoder.encodePassword password, salt
	}

	/**
	 * Quick check to see if the current user is logged in.
	 * @return <code>true</code> if the authenticated and not anonymous
	 */
	boolean isLoggedIn() {
		def authentication = SCH.context.authentication
		authentication && !authenticationTrustResolver.isAnonymous(authentication)
	}

	/**
	 * Call when editing, creating, or deleting a Requestmap to flush the cached
	 * configuration and rebuild using the most recent data.
	 */
	void clearCachedRequestmaps() {
		objectDefinitionSource?.reset()
	}

	/**
	 * Delete a role, and if Requestmap class is used to store roles, remove the role
	 * from all Requestmap definitions. If a Requestmap's config attribute is this role,
	 * it will be deleted.
	 *
	 * @param role the role to delete
	 */
	@Transactional
	void deleteRole(role) {
		def conf = SpringSecurityUtils.securityConfig
		String configAttributeName = conf.requestMap.configAttributeField
		String authorityFieldName = conf.authority.nameField

		if (SpringSecurityUtils.securityConfigType == 'Requestmap') {
			String roleName = role."$authorityFieldName"
			def requestmaps = findRequestmapsByRole(roleName, conf)
			for (rm in requestmaps) {
				String configAttribute = rm."$configAttributeName"
				if (configAttribute.equals(roleName)) {
					rm.delete(flush: true)
				}
				else {
					List parts = configAttribute.split(',')*.trim()
					parts.remove roleName
					rm."$configAttributeName" = parts.join(',')
				}
			}
			clearCachedRequestmaps()
		}

		// remove the role grant from all users
		def joinClass = grailsApplication.getClassForName(conf.userLookup.authorityJoinClassName)
		joinClass.removeAll role

		role.delete(flush: true)
	}

	/**
	 * Update a role, and if Requestmap class is used to store roles, replace the new role
	 * name in all Requestmap definitions that use it if the name was changed.
	 *
	 * @param role the role to update
	 * @param newProperties the new role attributes ('params' from the calling controller)
	 */
	@Transactional
	boolean updateRole(role, newProperties) {

		def conf = SpringSecurityUtils.securityConfig
		String configAttributeName = conf.requestMap.configAttributeField
		String authorityFieldName = conf.authority.nameField

		String oldRoleName = role."$authorityFieldName"
		role.properties = newProperties

		role.save()
		if (role.hasErrors()) {
			return false
		}

		if (SpringSecurityUtils.securityConfigType == 'Requestmap') {
			String newRoleName = role."$authorityFieldName"
			if (newRoleName != oldRoleName) {
				def requestmaps = findRequestmapsByRole(oldRoleName, conf)
				for (rm in requestmaps) {
					rm."$configAttributeName" = rm."$configAttributeName".replace(oldRoleName, newRoleName)
				}
			}
			clearCachedRequestmaps()
		}

		true
	}

	/**
	 * Rebuild an Authentication for the given username and register it in the security context.
	 * Typically used after updating a user's authorities or other auth-cached info.
	 * <p/>
	 * Also removes the user from the user cache to force a refresh at next login.
	 *
	 * @param username the user's login name
	 * @param password optional
	 */
	void reauthenticate(String username, String password = null) {
		SpringSecurityUtils.reauthenticate username, password
	}

	/**
	 * Check if the request was triggered by an Ajax call.
	 * @param request the request
	 * @return <code>true</code> if Ajax
	 */
	boolean isAjax(HttpServletRequest request) {
		SpringSecurityUtils.isAjax request
	}

	protected List findRequestmapsByRole(String roleName, conf) {
		def domainClass = grailsApplication.getClassForName(conf.requestMap.className)
		String configAttributeName = conf.requestMap.configAttributeField
		domainClass.withCriteria {
			like configAttributeName, "%$roleName%"
		}
	}
}
