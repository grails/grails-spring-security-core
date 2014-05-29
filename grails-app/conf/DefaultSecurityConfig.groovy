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
import grails.plugin.springsecurity.SecurityConfigType
import grails.plugin.springsecurity.SpringSecurityUtils
import grails.plugin.springsecurity.authentication.GrailsAnonymousAuthenticationToken

import org.springframework.security.authentication.RememberMeAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.security.web.authentication.rememberme.AbstractRememberMeServices
import org.springframework.security.web.authentication.rememberme.PersistentTokenBasedRememberMeServices
import org.springframework.security.web.authentication.switchuser.SwitchUserFilter
import org.springframework.security.web.context.HttpSessionSecurityContextRepository

security {

	/** misc properties */

	active = true

	printStatusMessages = true

	ajaxHeader = 'X-Requested-With'
	ajaxCheckClosure = null

	registerLoggerListener = false

	// 'strict' mode where an explicit grant is required to access any resource;
	// if true make sure to allow IS_AUTHENTICATED_ANONYMOUSLY or permitAll
	// for /, /index.gsp, /js/**, /css/**, /images/**, /login/**, /logout/**, /assets/**, etc.
	// Also consider using fii.rejectPublicInvocations = true
	rejectIfNoRule = true

	// hierarchical roles
	roleHierarchy = ''

	// ip restriction filter
	ipRestrictions = [:]

	// voters
	voterNames = [] // 'authenticatedVoter', 'roleVoter', 'closureVoter'

	// providers
	providerNames = [] // 'daoAuthenticationProvider', 'anonymousAuthenticationProvider', 'rememberMeAuthenticationProvider'

	// AfterInvocationManager
	afterInvocationManagerProviderNames = []

	// HttpSessionEventPublisher
	useHttpSessionEventPublisher = false

	// SecurityEventListener
	useSecurityEventListener = false

	// user caching
	cacheUsers = false

	// user and role class properties
	userLookup {
		userDomainClassName = null // must be set if using UserDetailsService
		usernamePropertyName = 'username'
		enabledPropertyName = 'enabled'
		passwordPropertyName = 'password'
		authoritiesPropertyName = 'authorities'
		accountExpiredPropertyName = 'accountExpired'
		accountLockedPropertyName = 'accountLocked'
		passwordExpiredPropertyName = 'passwordExpired'
		authorityJoinClassName = null // must be set if using UserDetailsService
	}
	authority {
		className = null // must be set if using UserDetailsService
		nameField = 'authority'
		groupAuthorityNameField = null //must be set if using authority groups
	}
	useRoleGroups = false

	/** authenticationProcessingFilter */
	apf {
		filterProcessesUrl = '/j_spring_security_check'
		usernameParameter = UsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_USERNAME_KEY // 'j_username'
		passwordParameter = UsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_PASSWORD_KEY // 'j_password'
		continueChainBeforeSuccessfulAuthentication = false
		allowSessionCreation = true
		postOnly = true
		storeLastUsername = false
	}

	// authenticationFailureHandler
	failureHandler {
		defaultFailureUrl = '/login/authfail?login_error=1'
		ajaxAuthFailUrl = '/login/authfail?ajax=true'
		exceptionMappings = [:]
		useForward = false
		allowSessionCreation = true
	}

	// successHandler
	successHandler {
		defaultTargetUrl = '/'
		alwaysUseDefault = false
		targetUrlParameter = SpringSecurityUtils.DEFAULT_TARGET_PARAMETER // 'spring-security-redirect'
		ajaxSuccessUrl = '/login/ajaxSuccess'
		useReferer = false
	}

	// requestCache
	requestCache {
		createSession = true
	}

	// redirectStrategy
	redirectStrategy {
		contextRelative = false
	}

	// session fixation prevention
	useSessionFixationPrevention = true
	sessionFixationPrevention {
		migrate = true
		alwaysCreateSession = false
	}

	/** daoAuthenticationProvider **/
	dao {
		reflectionSaltSourceProperty = null // if null, don't use salt source
		hideUserNotFoundExceptions = true
	}

	/** anonymousProcessingFilter */
	anon {
		key = 'foo'
	}

	/** authenticationEntryPoint */
	auth {
		loginFormUrl = '/login/auth'
		forceHttps = false
		ajaxLoginFormUrl = '/login/authAjax'
		useForward = false // redirect to login page
	}

	/** logoutFilter */
	logout {
		afterLogoutUrl = '/'
		filterProcessesUrl = '/j_spring_security_logout'
		handlerNames = [] // 'rememberMeServices', 'securityContextLogoutHandler'
		clearAuthentication = true
		invalidateHttpSession = true
		targetUrlParameter = null
		alwaysUseDefaultTargetUrl = false
		redirectToReferer = false
		postOnly = true
	}

	/**
	 * accessDeniedHandler
	 * set errorPage to null to send Error 403 instead of showing error page
	 */
	adh {
		errorPage = '/login/denied'
		ajaxErrorPage = '/login/ajaxDenied'
		useForward = true
	}

	/** passwordEncoder */
	// see http://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html
	password {
		algorithm = 'bcrypt'
		encodeHashAsBase64 = false
		bcrypt {
			logrounds = 10
		}
		hash {
			iterations = 10000
		}
	}

	/** rememberMeServices */
	rememberMe {
		cookieName = 'grails_remember_me'
		alwaysRemember = false
		tokenValiditySeconds = AbstractRememberMeServices.TWO_WEEKS_S // 1209600 -> 14 days
		parameter = AbstractRememberMeServices.DEFAULT_PARAMETER // '_spring_security_remember_me'
		key = 'grailsRocks'
		persistent = false
		persistentToken {
			domainClassName = null
			seriesLength = PersistentTokenBasedRememberMeServices.DEFAULT_SERIES_LENGTH // 16
			tokenLength = PersistentTokenBasedRememberMeServices.DEFAULT_TOKEN_LENGTH // 16
		}
		useSecureCookie = null
		createSessionOnSuccess = true
	}

	/** URL <-> Role mapping */

	// default to annotation mode
	securityConfigType = SecurityConfigType.Annotation

	// use Requestmap domain class to store rules in the database
	// 	change securityConfigType to 'Requestmap'
	requestMap {
		className = null // must be set if using
		urlField = 'url'
		configAttributeField = 'configAttribute'
		httpMethodField = 'httpMethod'
	}

	// use annotations from Controllers to define security rules
	// 	change securityConfigType to 'Annotation'
	controllerAnnotations {
		staticRules = [:]
	}

	// use a Map of URL -> roles to define security rules
	// or List of Maps where the keys are pattern (URL pattern),
	// access (single token or List, e.g. role name(s)), httpMethod (optional restriction to particular method)
	// 	to use, change securityConfigType to 'InterceptUrlMap'
	interceptUrlMap = null

	/** basic auth */
	useBasicAuth = false
	basic {
		realmName = 'Grails Realm'
		credentialsCharset = 'UTF-8'
	}

	/** digest auth */
	useDigestAuth = false
	digest {
		realmName = 'Grails Realm'
		key = 'changeme'
		nonceValiditySeconds = 300
		passwordAlreadyEncoded = false
		createAuthenticatedToken = false
		useCleartextPasswords = false
	}

	/** use switchUserProcessingFilter */
	useSwitchUserFilter = false
	switchUser {
		switchUserUrl = '/j_spring_security_switch_user'
		exitUserUrl = '/j_spring_security_exit_user'
		targetUrl = null // use the authenticationSuccessHandler
		switchFailureUrl = null // use the authenticationFailureHandler
		usernameParameter = SwitchUserFilter.SPRING_SECURITY_SWITCH_USERNAME_KEY // j_username
	}

	// port mappings
	portMapper {
		httpPort = 8080
		httpsPort = 8443
	}

	// secure channel filter (http/https)
	secureChannel {
		definition = [:]
		useHeaderCheckChannelSecurity = false
		secureHeaderName = 'X-Forwarded-Proto'
		secureHeaderValue = 'http'
		insecureHeaderName = 'X-Forwarded-Proto'
		insecureHeaderValue = 'https'
	}

	// X509
	useX509 = false
	x509 {
		continueFilterChainOnUnsuccessfulAuthentication = true
		subjectDnRegex = 'CN=(.*?)(?:,|$)'
		subjectDnClosure = null
		checkForPrincipalChanges = false
		invalidateSessionOnPrincipalChange = true
		throwExceptionWhenTokenRejected = false
	}

	// authenticationTrustResolver
	atr {
		anonymousClass = GrailsAnonymousAuthenticationToken
		rememberMeClass = RememberMeAuthenticationToken
	}

	// providerManager
	providerManager {
		eraseCredentialsAfterAuthentication = true
	}

	// securityContextRepository
	scr {
		allowSessionCreation = true
		disableUrlRewriting = true
		springSecurityContextKey = HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY // 'SPRING_SECURITY_CONTEXT'
	}

	// securityContextPersistenceFilter
	scpf {
		forceEagerSessionCreation = false
	}

	// filterInvocationInterceptor
	fii {
		alwaysReauthenticate = false
		rejectPublicInvocations = true
		validateConfigAttributes = true
		publishAuthorizationSuccess = false
		observeOncePerRequest = true
	}

	debug {
		useFilter = false
	}

	// SecurityContextHolder
	sch {
		// one of MODE_THREADLOCAL, MODE_INHERITABLETHREADLOCAL, MODE_GLOBAL,
		// or the name of a class implementing org.springframework.security.core.context.SecurityContextHolderStrategy
		strategyName = SecurityContextHolder.MODE_THREADLOCAL
	}
}
