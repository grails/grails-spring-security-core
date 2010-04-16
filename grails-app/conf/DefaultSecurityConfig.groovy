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
import org.springframework.security.authentication.AnonymousAuthenticationToken
import org.springframework.security.authentication.RememberMeAuthenticationToken
import org.springframework.security.web.authentication.WebAuthenticationDetails
import org.codehaus.groovy.grails.plugins.springsecurity.SecurityConfigType

security {

	/** misc properties */

	active = true

	ajaxHeader = 'X-Requested-With'

	// 'strict' mode where an explicit grant is required to access any resource;
	// if true make sure to allow IS_AUTHENTICATED_ANONYMOUSLY 
	// for /, /js/**, /css/**, /images/**, /login/**, /logout/**, etc. 
	rejectIfNoRule = false

	/** error messages */
	errors.login.disabled = "Sorry, your account is disabled."
	errors.login.fail = "Sorry, we were not able to find a user with that username and password."

	// hierarchical roles
	roleHierarchy = ''

	// ip restriction filter
	ipRestrictions = [:]

	// voters
	voterNames = ['authenticatedVoter', 'roleVoter']

	// providers
	providerNames = ['daoAuthenticationProvider',
	                 'anonymousAuthenticationProvider',
	                 'rememberMeAuthenticationProvider']

	// HttpSessionEventPublisher
	useHttpSessionEventPublisher = false

	// SecurityEventListener
	useSecurityEventListener = false

	// user caching
	cacheUsers = false

	// user and role class properties
	userLookup.userDomainClassName = 'Person'
	userLookup.usernamePropertyName = 'username'
	userLookup.enabledPropertyName = 'enabled'
	userLookup.passwordPropertyName = 'password'
	userLookup.authoritiesPropertyName = 'authorities'
	authority.className = 'Authority'
	authority.nameField = 'authority'

	/** authenticationProcessingFilter */
	apf.filterProcessesUrl = '/j_spring_security_check'
	apf.usernameParameter = 'j_username'
	apf.passwordParameter = 'j_password'
	apf.continueChainBeforeSuccessfulAuthentication = false
	apf.allowSessionCreation = true
	apf.postOnly = true

	// failureHandler
	failureHandler.defaultFailureUrl  = '/login/authfail?login_error=1'
	failureHandler.ajaxAuthenticationFailureUrl = '/login/authfail?ajax=true'
	failureHandler.exceptionMappings = [:]
	failureHandler.useForward = false

	// successHandler
	successHandler.defaultTargetUrl = '/'
	successHandler.alwaysUseDefaultTargetUrl = false
	successHandler.targetUrlParameter = 'spring-security-redirect'
	successHandler.useReferer = false
	successHandler.ajaxSuccessUrl = '/login/ajaxSuccess'

	// requestCache
	requestCache.justUseSavedRequestOnGet = false
	requestCache.createSessionAllowed = true

	// redirectStrategy
	redirectStrategy.contextRelative = false

	// authenticationDetails
	authenticationDetails.authClass = WebAuthenticationDetails

	// session fixation
	useSessionFixation = false
	sessionFixation.migrate = true
	sessionFixation.alwaysCreateSession = false

	/** daoAuthenticationProvider **/
	dao.reflectionSaltSourceUserProperty = null // if null, don't use salt source

	/** anonymousProcessingFilter */
	anon.key = 'foo'
	anon.userAttribute = 'anonymousUser,ROLE_ANONYMOUS'

	/** authenticationEntryPoint */
	auth.loginFormUrl = '/login/auth'
	auth.forceHttps = 'false'
	auth.ajaxLoginFormUrl = '/login/authAjax'
	auth.useForward = false

	/** logoutFilter */
	logout.afterLogoutUrl = '/'
	logout.filterProcessesUrl = '/j_spring_security_logout'
	logout.handlerNames = ['rememberMeServices', 'securityContextLogoutHandler']

	/**
	 * accessDeniedHandler
	 * set errorPage to null to send Error 403 instead of showing error page
	 */
	adh.errorPage = '/login/denied'
	adh.ajaxErrorPage = '/login/ajaxDenied'

	/** passwordEncoder */
	// see http://java.sun.com/j2se/1.5.0/docs/guide/security/CryptoSpec.html#AppA
	password.algorithm = 'SHA-256'
	password.encodeHashAsBase64 = false

	/** rememberMeServices */
	rememberMe.cookieName = 'grails_remember_me'
	rememberMe.alwaysRemember = false
	rememberMe.tokenValiditySeconds = 1209600 //14 days
	rememberMe.parameter = '_spring_security_remember_me'
	rememberMe.key = 'grailsRocks'

	/** URL <-> Role mapping */

	// default to annotation mode
	securityConfigType = SecurityConfigType.Annotation
	// whether to use SpEL expressions
	securityConfig.useExpressions = false

	// use Requestmap domain class to store rules in the database
	// 	change securityConfigType to SecurityConfigType.Requestmap
	requestMap.className = 'Requestmap'
	requestMap.urlField = 'url'
	requestMap.configAttributeField = 'configAttribute'

	// use annotations from Controllers to define security rules
	// 	change securityConfigType to SecurityConfigType.Annotation
	controllerAnnotations.matcher = 'ant' // or 'regex'
	controllerAnnotations.matchesLowercase = true
	controllerAnnotations.staticRules = [:]

	// use a Map of URL -> roles to define security rules
	// 	change securityConfigType to SecurityConfigType.InterceptUrlMap
	interceptUrlMap = [:]

	/** basic auth */
	useBasicAuth = false
	basic.realmName = 'Grails Realm'

	/** use switchUserProcessingFilter */
	useSwitchUserFilter = false
	switchUser.switchUserUrl = '/j_spring_security_switch_user'
	switchUser.exitUserUrl = '/j_spring_security_exit_user'
	switchUser.targetUrl = '/'

	/** filterChainProxy */
	filterChain.stripQueryStringFromUrls = true

	// port mappings
	portMapper.httpPort = 8080
	portMapper.httpsPort = 8443

	// secure channel filter (http/https)
	secureChannel.definitionSource = ''
	secureChannel.config = [secure: [], insecure: []]

	// X509
	useX509 = false
	x509.continueFilterChainOnUnsuccessfulAuthentication = true
	x509.subjectDnRegex = 'CN=(.*?),'
	x509.checkForPrincipalChanges = false
	x509.invalidateSessionOnPrincipalChange = true
	x509.throwExceptionWhenTokenRejected = false

	// authenticationTrustResolver
	atr.anonymousClass = AnonymousAuthenticationToken
	atr.rememberMeClass = RememberMeAuthenticationToken
}
