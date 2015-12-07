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
import grails.plugin.springsecurity.ReflectionUtils
import grails.plugin.springsecurity.SecurityEventListener
import grails.plugin.springsecurity.SecurityFilterPosition
import grails.plugin.springsecurity.SpringSecurityUtils
import grails.plugin.springsecurity.access.NullAfterInvocationProvider
import grails.plugin.springsecurity.access.intercept.NullAfterInvocationManager
import grails.plugin.springsecurity.access.vote.AuthenticatedVetoableDecisionManager
import grails.plugin.springsecurity.access.vote.ClosureVoter
import grails.plugin.springsecurity.authentication.GrailsAnonymousAuthenticationProvider
import grails.plugin.springsecurity.authentication.NullAuthenticationEventPublisher
import grails.plugin.springsecurity.authentication.dao.NullSaltSource
import grails.plugin.springsecurity.authentication.encoding.BCryptPasswordEncoder
import grails.plugin.springsecurity.authentication.encoding.DigestAuthPasswordEncoder
import grails.plugin.springsecurity.authentication.encoding.PBKDF2PasswordEncoder
import grails.plugin.springsecurity.userdetails.DefaultPostAuthenticationChecks
import grails.plugin.springsecurity.userdetails.DefaultPreAuthenticationChecks
import grails.plugin.springsecurity.userdetails.GormUserDetailsService
import grails.plugin.springsecurity.web.GrailsRedirectStrategy
import grails.plugin.springsecurity.web.NullFilterChainValidator
import grails.plugin.springsecurity.web.SecurityRequestHolderFilter
import grails.plugin.springsecurity.web.access.AjaxAwareAccessDeniedHandler
import grails.plugin.springsecurity.web.access.DefaultThrowableAnalyzer
import grails.plugin.springsecurity.web.access.GrailsWebInvocationPrivilegeEvaluator
import grails.plugin.springsecurity.web.access.expression.WebExpressionVoter
import grails.plugin.springsecurity.web.access.intercept.AnnotationFilterInvocationDefinition
import grails.plugin.springsecurity.web.access.intercept.ChannelFilterInvocationSecurityMetadataSourceFactoryBean
import grails.plugin.springsecurity.web.access.intercept.InterceptUrlMapFilterInvocationDefinition
import grails.plugin.springsecurity.web.access.intercept.RequestmapFilterInvocationDefinition
import grails.plugin.springsecurity.web.authentication.AjaxAwareAuthenticationEntryPoint
import grails.plugin.springsecurity.web.authentication.AjaxAwareAuthenticationFailureHandler
import grails.plugin.springsecurity.web.authentication.AjaxAwareAuthenticationSuccessHandler
import grails.plugin.springsecurity.web.authentication.FilterProcessUrlRequestMatcher
import grails.plugin.springsecurity.web.authentication.GrailsUsernamePasswordAuthenticationFilter
import grails.plugin.springsecurity.web.authentication.logout.MutableLogoutFilter
import grails.plugin.springsecurity.web.authentication.preauth.x509.ClosureX509PrincipalExtractor
import grails.plugin.springsecurity.web.authentication.rememberme.GormPersistentTokenRepository
import grails.plugin.springsecurity.web.authentication.switchuser.NullSwitchUserAuthorityChanger
import grails.plugin.springsecurity.web.filter.DebugFilter
import grails.plugin.springsecurity.web.filter.GrailsAnonymousAuthenticationFilter
import grails.plugin.springsecurity.web.filter.GrailsRememberMeAuthenticationFilter
import grails.plugin.springsecurity.web.filter.IpAddressFilter
import grails.plugin.webxml.FilterManager

import javax.servlet.Filter

import org.codehaus.groovy.grails.commons.GrailsApplication
import org.codehaus.groovy.grails.commons.spring.GrailsApplicationContext
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.springframework.cache.ehcache.EhCacheFactoryBean
import org.springframework.cache.ehcache.EhCacheManagerFactoryBean
import org.springframework.expression.spel.standard.SpelExpressionParser
import org.springframework.security.access.event.LoggerListener
import org.springframework.security.access.expression.DenyAllPermissionEvaluator
import org.springframework.security.access.hierarchicalroles.RoleHierarchyAuthoritiesMapper
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl
import org.springframework.security.access.intercept.AfterInvocationProviderManager
import org.springframework.security.access.intercept.NullRunAsManager
import org.springframework.security.access.vote.AuthenticatedVoter
import org.springframework.security.access.vote.RoleHierarchyVoter
import org.springframework.security.authentication.AccountStatusUserDetailsChecker
import org.springframework.security.authentication.AuthenticationTrustResolverImpl
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher
import org.springframework.security.authentication.ProviderManager
import org.springframework.security.authentication.RememberMeAuthenticationProvider
import org.springframework.security.authentication.dao.DaoAuthenticationProvider
import org.springframework.security.authentication.dao.ReflectionSaltSource
import org.springframework.security.authentication.encoding.MessageDigestPasswordEncoder
import org.springframework.security.authentication.encoding.PlaintextPasswordEncoder
import org.springframework.security.core.context.SecurityContextHolder as SCH
import org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper
import org.springframework.security.core.userdetails.cache.EhCacheBasedUserCache
import org.springframework.security.core.userdetails.cache.NullUserCache
import org.springframework.security.web.FilterChainProxy
import org.springframework.security.web.PortMapperImpl
import org.springframework.security.web.PortResolverImpl
import org.springframework.security.web.access.AccessDeniedHandlerImpl
import org.springframework.security.web.access.ExceptionTranslationFilter
import org.springframework.security.web.access.channel.ChannelDecisionManagerImpl
import org.springframework.security.web.access.channel.ChannelProcessingFilter
import org.springframework.security.web.access.channel.InsecureChannelProcessor
import org.springframework.security.web.access.channel.RetryWithHttpEntryPoint
import org.springframework.security.web.access.channel.RetryWithHttpsEntryPoint
import org.springframework.security.web.access.channel.SecureChannelProcessor
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider
import org.springframework.security.web.authentication.preauth.x509.SubjectDnX509PrincipalExtractor
import org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter
import org.springframework.security.web.authentication.rememberme.InMemoryTokenRepositoryImpl
import org.springframework.security.web.authentication.rememberme.PersistentTokenBasedRememberMeServices
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy
import org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy
import org.springframework.security.web.authentication.switchuser.SwitchUserFilter
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter
import org.springframework.security.web.authentication.www.DigestAuthenticationEntryPoint
import org.springframework.security.web.authentication.www.DigestAuthenticationFilter
import org.springframework.security.web.context.HttpSessionSecurityContextRepository
import org.springframework.security.web.context.SecurityContextPersistenceFilter
import org.springframework.security.web.firewall.DefaultHttpFirewall
import org.springframework.security.web.savedrequest.HttpSessionRequestCache
import org.springframework.security.web.savedrequest.NullRequestCache
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter
import org.springframework.security.web.session.HttpSessionEventPublisher
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import org.springframework.security.web.util.matcher.AnyRequestMatcher
import org.springframework.security.web.util.matcher.RequestMatcher
import org.springframework.web.filter.DelegatingFilterProxy

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class SpringSecurityCoreGrailsPlugin {

	private final Logger log = LoggerFactory.getLogger('grails.plugin.springsecurity.SpringSecurityCoreGrailsPlugin')

	String version = '2.0.0'
	String grailsVersion = '2.3.0 > *'
	List observe = ['controllers']
	List loadAfter = ['controllers', 'hibernate', 'hibernate4', 'hibernate5', 'services']
	List pluginExcludes = [
		'docs/**',
		'grails-app/domain/**',
		'src/docs/**'
	]
	String author = 'Burt Beckwith'
	String authorEmail = 'burt@burtbeckwith.com'
	String title = 'Spring Security Core Plugin'
	String description = 'Spring Security Core plugin'
	String documentation = 'http://grails-plugins.github.io/grails-spring-security-core/'
	String license = 'APACHE'
	def organization = [name: 'Grails', url: 'http://www.grails.org/']
	def issueManagement = [url: 'https://github.com/grails-plugins/grails-spring-security-core/issues']
	def scm = [url: 'https://github.com/grails-plugins/grails-spring-security-core']

	// make sure the filter chain filter is after the Grails filter
	def getWebXmlFilterOrder() {
		[springSecurityFilterChain: FilterManager.GRAILS_WEB_REQUEST_POSITION + 100]
	}

	def doWithWebDescriptor = { xml ->

		SpringSecurityUtils.resetSecurityConfig()

		ReflectionUtils.application = application

		def conf = SpringSecurityUtils.securityConfig
		if (!conf || !conf.active) {
			return
		}

		// we add the filter(s) right after the last context-param
		def contextParam = xml.'context-param'

		contextParam[contextParam.size() - 1] + {
			filter {
				'filter-name'('springSecurityFilterChain')
				'filter-class'(DelegatingFilterProxy.name)
			}
		}

		// add the filter-mapping after the Spring character encoding filter
		findMappingLocation.delegate = delegate
		def mappingLocation = findMappingLocation(xml)
		mappingLocation + {
			'filter-mapping' {
				'filter-name'('springSecurityFilterChain')
				'url-pattern'('/*')
				dispatcher('ERROR')
				dispatcher('REQUEST')
			}
		}

		if (conf.useHttpSessionEventPublisher) {
			log.trace 'Configuring HttpSessionEventPublisher'

			def filterMapping = xml.'filter-mapping'
			filterMapping[filterMapping.size() - 1] + {
				listener {
					'listener-class'(HttpSessionEventPublisher.name)
				}
			}
		}
	}

	def doWithSpring = {

		ReflectionUtils.application = application

		if (application.warDeployed) {
			// need to reset here since web.xml was already built, so
			// doWithWebDescriptor isn't called when deployed as war
			SpringSecurityUtils.resetSecurityConfig()
		}

		SpringSecurityUtils.application = application

		def conf = SpringSecurityUtils.securityConfig
		boolean printStatusMessages = (conf.printStatusMessages instanceof Boolean) ? conf.printStatusMessages : true
		if (!conf || !conf.active) {
			if (printStatusMessages) {
				println '\n\nSpring Security is disabled, not loading\n\n'
			}
			return
		}

		log.trace 'doWithSpring'

		if (printStatusMessages) {
			println '\nConfiguring Spring Security Core ...'
		}

		if (log.traceEnabled) {
			def sb = new StringBuilder('Spring Security configuration:\n')
			conf.flatten().each { key, value ->
				sb << '\t' << key << ': '
				if (value instanceof Closure) {
					sb << '(closure)'
				}
				else {
					try {
						sb << value.toString() // eagerly convert to string to catch individual exceptions
					}
					catch (e) {
						sb << '(an error occurred: ' << e.message << ')'
					}
				}
				sb << '\n'
			}
			log.trace sb.toString()
		}

		createRefList.delegate = delegate

		/** springSecurityFilterChain */
		configureFilterChain.delegate = delegate
		configureFilterChain conf

		// securityRequestHolderFilter
		securityRequestHolderFilter(SecurityRequestHolderFilter) {
			useHeaderCheckChannelSecurity = conf.secureChannel.useHeaderCheckChannelSecurity
			secureHeaderName = conf.secureChannel.secureHeaderName // 'X-Forwarded-Proto'
			secureHeaderValue = conf.secureChannel.secureHeaderValue // 'http'
			insecureHeaderName = conf.secureChannel.insecureHeaderName // 'X-Forwarded-Proto'
			insecureHeaderValue = conf.secureChannel.insecureHeaderValue // 'https'
			portMapper = ref('portMapper')
			portResolver = ref('portResolver')
		}

		// logout
		configureLogout.delegate = delegate
		configureLogout conf

		/** securityContextRepository */
		securityContextRepository(HttpSessionSecurityContextRepository) {
			allowSessionCreation = conf.scr.allowSessionCreation // true
			disableUrlRewriting = conf.scr.disableUrlRewriting // true
			springSecurityContextKey = conf.scr.springSecurityContextKey // SPRING_SECURITY_CONTEXT
		}

		/** securityContextPersistenceFilter */
		securityContextPersistenceFilter(SecurityContextPersistenceFilter, ref('securityContextRepository')) {
			forceEagerSessionCreation = conf.scpf.forceEagerSessionCreation // false
		}

		/** authenticationProcessingFilter */
		configureAuthenticationProcessingFilter.delegate = delegate
		configureAuthenticationProcessingFilter conf

		/** securityContextHolderAwareRequestFilter */
		securityContextHolderAwareRequestFilter(SecurityContextHolderAwareRequestFilter) {
			authenticationEntryPoint = ref('authenticationEntryPoint')
			authenticationManager = ref('authenticationManager')
			logoutHandlers = ref('logoutHandlers')
		}

		/** rememberMeAuthenticationFilter */
		rememberMeAuthenticationFilter(GrailsRememberMeAuthenticationFilter,
		                               ref('authenticationManager'), ref('rememberMeServices'), ref('requestCache')) {
			authenticationSuccessHandler = ref('authenticationSuccessHandler')
			createSessionOnSuccess = conf.rememberMe.createSessionOnSuccess // true
		}

		userDetailsChecker(AccountStatusUserDetailsChecker)

		authoritiesMapper(RoleHierarchyAuthoritiesMapper, ref('roleHierarchy'))

		/** rememberMeServices */
		if (conf.rememberMe.persistent) {
			log.trace 'Configuring persistent remember-me'
			rememberMeServices(PersistentTokenBasedRememberMeServices, conf.rememberMe.key, ref('userDetailsService'), ref('tokenRepository')) {
				cookieName = conf.rememberMe.cookieName
				alwaysRemember = conf.rememberMe.alwaysRemember
				tokenValiditySeconds = conf.rememberMe.tokenValiditySeconds
				parameter = conf.rememberMe.parameter
				if (conf.rememberMe.useSecureCookie instanceof Boolean) {
					useSecureCookie = conf.rememberMe.useSecureCookie // null
				}
				authenticationDetailsSource = ref('authenticationDetailsSource')
				userDetailsChecker = ref('userDetailsChecker')
				authoritiesMapper = ref('authoritiesMapper')

				seriesLength = conf.rememberMe.persistentToken.seriesLength // 16
				tokenLength = conf.rememberMe.persistentToken.tokenLength // 16
			}

			tokenRepository(GormPersistentTokenRepository)
		}
		else {
			log.trace 'Configuring non-persistent remember-me'
			rememberMeServices(TokenBasedRememberMeServices, conf.rememberMe.key, ref('userDetailsService')) {
				cookieName = conf.rememberMe.cookieName
				alwaysRemember = conf.rememberMe.alwaysRemember
				tokenValiditySeconds = conf.rememberMe.tokenValiditySeconds
				parameter = conf.rememberMe.parameter
				if (conf.rememberMe.useSecureCookie instanceof Boolean) {
					useSecureCookie = conf.rememberMe.useSecureCookie // null
				}
				authenticationDetailsSource = ref('authenticationDetailsSource')
				userDetailsChecker = ref('userDetailsChecker')
				authoritiesMapper = ref('authoritiesMapper')
			}

			// register a lightweight impl so there's a bean in either case
			tokenRepository(InMemoryTokenRepositoryImpl)
		}

		/** anonymousAuthenticationFilter */
		anonymousAuthenticationFilter(GrailsAnonymousAuthenticationFilter) {
			authenticationDetailsSource = ref('authenticationDetailsSource')
			key = conf.anon.key
		}

		throwableAnalyzer(DefaultThrowableAnalyzer)

		/** exceptionTranslationFilter */
		exceptionTranslationFilter(ExceptionTranslationFilter, ref('authenticationEntryPoint'), ref('requestCache')) {
			accessDeniedHandler = ref('accessDeniedHandler')
			authenticationTrustResolver = ref('authenticationTrustResolver')
			throwableAnalyzer = ref('throwableAnalyzer')
		}
		accessDeniedHandler(AjaxAwareAccessDeniedHandler) {
			errorPage = conf.adh.errorPage == 'null' ? null : conf.adh.errorPage // '/login/denied' or 403
			ajaxErrorPage = conf.adh.ajaxErrorPage
			useForward = conf.adh.useForward
			portResolver = ref('portResolver')
			authenticationTrustResolver = ref('authenticationTrustResolver')
			requestCache = ref('requestCache')
		}

		/** authenticationTrustResolver */
		authenticationTrustResolver(AuthenticationTrustResolverImpl) {
			anonymousClass = conf.atr.anonymousClass
			rememberMeClass = conf.atr.rememberMeClass
		}

		// default 'authenticationEntryPoint'
		authenticationEntryPoint(AjaxAwareAuthenticationEntryPoint, conf.auth.loginFormUrl) { // '/login/auth'
			ajaxLoginFormUrl = conf.auth.ajaxLoginFormUrl // '/login/authAjax'
			forceHttps = conf.auth.forceHttps // false
			useForward = conf.auth.useForward // false
			portMapper = ref('portMapper')
			portResolver = ref('portResolver')
			redirectStrategy = ref('redirectStrategy')
		}

		/** filterInvocationInterceptor */

		// TODO doc new
		if (conf.afterInvocationManagerProviderNames) {
			log.trace 'Configuring AfterInvocationProviderManager'
			afterInvocationManager(AfterInvocationProviderManager) {
				providers = [new NullAfterInvocationProvider()] // will be replaced in doWithApplicationContext
			}
		}
		else {
			// register a lightweight impl so there's a bean in either case
			afterInvocationManager(NullAfterInvocationManager)
		}

		filterInvocationInterceptor(FilterSecurityInterceptor) {
			authenticationManager = ref('authenticationManager')
			accessDecisionManager = ref('accessDecisionManager')
			securityMetadataSource = ref('objectDefinitionSource')
			runAsManager = ref('runAsManager')
			afterInvocationManager = ref('afterInvocationManager')
			alwaysReauthenticate = conf.fii.alwaysReauthenticate // false
			rejectPublicInvocations = conf.fii.rejectPublicInvocations // true
			validateConfigAttributes = conf.fii.validateConfigAttributes // true
			publishAuthorizationSuccess = conf.fii.publishAuthorizationSuccess // false
			observeOncePerRequest = conf.fii.observeOncePerRequest // true
		}

		String securityConfigType = SpringSecurityUtils.securityConfigType
		log.trace "Using security config type '{}'", securityConfigType
		if (securityConfigType != 'Annotation' &&
				securityConfigType != 'Requestmap' &&
				securityConfigType != 'InterceptUrlMap') {
			println """
ERROR: the 'securityConfigType' property must be one of
'Annotation', 'Requestmap', or 'InterceptUrlMap' or left unspecified
to default to 'Annotation'; setting value to 'Annotation'
"""
			securityConfigType = 'Annotation'
		}

		if (securityConfigType == 'Annotation') {
			objectDefinitionSource(AnnotationFilterInvocationDefinition) {
				application = ref('grailsApplication')
				grailsUrlConverter = ref('grailsUrlConverter')
				responseMimeTypesApi = ref('responseMimeTypesApi')
				boolean lowercase = conf.controllerAnnotations.lowercase // true
				if (conf.rejectIfNoRule instanceof Boolean) {
					rejectIfNoRule = conf.rejectIfNoRule
				}
			}
		}
		else if (securityConfigType == 'Requestmap') {
			objectDefinitionSource(RequestmapFilterInvocationDefinition) {
				if (conf.rejectIfNoRule instanceof Boolean) {
					rejectIfNoRule = conf.rejectIfNoRule
				}
			}
		}
		else if (securityConfigType == 'InterceptUrlMap') {
			objectDefinitionSource(InterceptUrlMapFilterInvocationDefinition) {
				if (conf.rejectIfNoRule instanceof Boolean) {
					rejectIfNoRule = conf.rejectIfNoRule
				}
			}
		}

		webInvocationPrivilegeEvaluator(GrailsWebInvocationPrivilegeEvaluator,
				ref('filterInvocationInterceptor'))

		// voters
		configureVoters.delegate = delegate
		configureVoters conf

		/** anonymousAuthenticationProvider */
		anonymousAuthenticationProvider(GrailsAnonymousAuthenticationProvider)

		/** rememberMeAuthenticationProvider */
		rememberMeAuthenticationProvider(RememberMeAuthenticationProvider, conf.rememberMe.key)

		// authenticationManager
		configureAuthenticationManager.delegate = delegate
		configureAuthenticationManager conf

		/** daoAuthenticationProvider */
		String reflectionSaltSourceProperty = conf.dao.reflectionSaltSourceProperty
		if (reflectionSaltSourceProperty) {
			log.trace "Using reflectionSaltSourceProperty '{}'", reflectionSaltSourceProperty
			saltSource(ReflectionSaltSource) {
				userPropertyToUse = reflectionSaltSourceProperty
			}
		}
		else {
			saltSource(NullSaltSource)
		}

		preAuthenticationChecks(DefaultPreAuthenticationChecks)
		postAuthenticationChecks(DefaultPostAuthenticationChecks)

		daoAuthenticationProvider(DaoAuthenticationProvider) {
			userDetailsService = ref('userDetailsService')
			passwordEncoder = ref('passwordEncoder')
			userCache = ref('userCache')
			saltSource = ref('saltSource')
			preAuthenticationChecks = ref('preAuthenticationChecks')
			postAuthenticationChecks = ref('postAuthenticationChecks')
			authoritiesMapper = ref('authoritiesMapper')
			hideUserNotFoundExceptions = conf.dao.hideUserNotFoundExceptions // true
		}

		/** passwordEncoder */
		if (conf.password.algorithm == 'bcrypt') {
			log.trace 'Using bcrypt'
			passwordEncoder(BCryptPasswordEncoder, conf.password.bcrypt.logrounds) // 10
		}
		else if (conf.password.algorithm == 'pbkdf2') {
			log.trace 'Using pbkdf2'
			passwordEncoder(PBKDF2PasswordEncoder)
		}
		else {
			log.trace "Using password algorithm '{}'", conf.password.algorithm
			passwordEncoder(MessageDigestPasswordEncoder, conf.password.algorithm) {
				encodeHashAsBase64 = conf.password.encodeHashAsBase64 // false
				iterations = conf.password.hash.iterations // 10000
			}
		}

		/** userDetailsService */
		userDetailsService(GormUserDetailsService) {
			grailsApplication = ref('grailsApplication')
		}

		/** authenticationUserDetailsService */
		authenticationUserDetailsService(UserDetailsByNameServiceWrapper, ref('userDetailsService'))

		// port mappings for channel security, etc.
		portMapper(PortMapperImpl) {
			portMappings = [(conf.portMapper.httpPort.toString()) : conf.portMapper.httpsPort.toString()] // 8080, 8443

		}
		portResolver(PortResolverImpl) {
			portMapper = ref('portMapper')
		}

		// SecurityEventListener
		if (conf.useSecurityEventListener) {
			log.trace 'Configuring SecurityEventListener'
			securityEventListener(SecurityEventListener)

			authenticationEventPublisher(DefaultAuthenticationEventPublisher)
		}
		else {
			authenticationEventPublisher(NullAuthenticationEventPublisher)
		}

		// Basic Auth
		if (conf.useBasicAuth) {
			log.trace 'Configuring Basic auth'
			configureBasicAuth.delegate = delegate
			configureBasicAuth conf
		}

		// Digest Auth
		if (conf.useDigestAuth) {
			log.trace 'Configuring Digest auth'
			configureDigestAuth.delegate = delegate
			configureDigestAuth conf
		}

		// Switch User
		if (conf.useSwitchUserFilter) {

			log.trace 'Configuring SwitchUserFilter'

			// TODO doc new
			switchUserAuthorityChanger(NullSwitchUserAuthorityChanger)

			switchUserProcessingFilter(SwitchUserFilter) {
				userDetailsService = ref('userDetailsService')
				userDetailsChecker = ref('userDetailsChecker')
				authenticationDetailsSource = ref('authenticationDetailsSource')
				switchUserAuthorityChanger = ref('switchUserAuthorityChanger')
				switchUserUrl = conf.switchUser.switchUserUrl // '/j_spring_security_switch_user'
				exitUserUrl = conf.switchUser.exitUserUrl // '/j_spring_security_exit_user'
				usernameParameter = conf.switchUser.usernameParameter // '/j_spring_security_exit_user'
				if (conf.switchUser.targetUrl) {
					targetUrl = conf.switchUser.targetUrl
				}
				else {
					successHandler = ref('authenticationSuccessHandler')
				}
				if (conf.switchUser.switchFailureUrl) {
					switchFailureUrl = conf.switchUser.switchFailureUrl
				}
				else {
					failureHandler = ref('authenticationFailureHandler')
				}
			}
		}

		// per-method run-as, defined here so it can be overridden
		runAsManager(NullRunAsManager)

		// x509
		if (conf.useX509) {
			log.trace 'Configuring X.509'
			configureX509.delegate = delegate
			configureX509 conf
		}

		// channel (http/https) security
		if (conf.secureChannel.definition) {
			log.trace 'Configuring channel security'
			configureChannelProcessingFilter.delegate = delegate
			configureChannelProcessingFilter conf
		}

		// IP filter
		if (conf.ipRestrictions) {
			log.trace 'Configuring IP restrictions'
			configureIpFilter.delegate = delegate
			configureIpFilter conf
		}

		// user details cache
		if (conf.cacheUsers) {
			log.trace 'Configuring user cache'
			userCache(EhCacheBasedUserCache) {
				cache = ref('securityUserCache')
			}
			securityUserCache(EhCacheFactoryBean) {
				cacheManager = ref('cacheManager')
				cacheName = 'userCache'
			}
			cacheManager(EhCacheManagerFactoryBean) {
				cacheManagerName = 'spring-security-core-user-cache-' + UUID.randomUUID()
			}
		}
		else {
			userCache(NullUserCache)
		}

		/** loggerListener */
		if (conf.registerLoggerListener) {
			log.trace 'Register LoggerListener'
			loggerListener(LoggerListener)
		}

		if (conf.debug.useFilter) {
			log.trace 'Register DebugFilter'
			securityDebugFilter(DebugFilter, ref('springSecurityFilterChain'))
		}

		permissionEvaluator(DenyAllPermissionEvaluator)

		if (printStatusMessages) {
			println '... finished configuring Spring Security Core\n'
		}
	}

	def doWithDynamicMethods = { ctx ->

		ReflectionUtils.application = application

		def conf = SpringSecurityUtils.securityConfig
		if (!conf || !conf.active) {
			return
		}

		log.trace 'doWithDynamicMethods'

		for (controllerClass in application.controllerClasses) {
			addControllerMethods controllerClass.metaClass, ctx
		}

		if (SpringSecurityUtils.securityConfigType == 'Annotation') {
			initializeFromAnnotations ctx, conf, application
		}
	}

	def doWithApplicationContext = { ctx ->

		ReflectionUtils.application = application

		def conf = SpringSecurityUtils.securityConfig
		if (!conf || !conf.active) {
			return
		}

		log.trace 'doWithApplicationContext'

		/**
		 * Specify the field of the role hierarchy bean
		 * if the role hierarchy is backed by a domain object use this instead of roleHierarchy config param
		 * @author fpape
		 */
		String roleHierarchy
		if (conf.roleHierarchyEntryClassName) {
			log.trace 'Loading persistent role hierarchy'
			Class roleHierarchyEntryClass = Class.forName(conf.roleHierarchyEntryClassName)
			roleHierarchyEntryClass.withTransaction {
				roleHierarchy = roleHierarchyEntryClass.list()*.entry.join('\n')
			}
		}
		else {
			roleHierarchy = conf.roleHierarchy
		}

		ctx.roleHierarchy.hierarchy = roleHierarchy

		def strategyName = conf.sch.strategyName
		if (strategyName instanceof CharSequence) {
			SCH.setStrategyName strategyName.toString()
		}
		log.trace 'Using SecurityContextHolder strategy {}', SCH.strategyName

		// build filters here to give dependent plugins a chance to register some
		def filterChain = ctx.springSecurityFilterChain
		Map<RequestMatcher, List<Filter>> filterChainMap = [:]

		SortedMap<Integer, String> filterNames = findFilterChainNames(conf)
		def allConfiguredFilters = [:]
		filterNames.each { int order, String name ->
			def filter = ctx.getBean(name)
			allConfiguredFilters[name] = filter
			SpringSecurityUtils.configuredOrderedFilters[order] = filter
		}
		log.trace 'Ordered filters: {}', SpringSecurityUtils.configuredOrderedFilters

		if (conf.filterChain.chainMap) {
			conf.filterChain.chainMap.each { key, value ->
				value = value.toString().trim()
				def filters
				if (value.toLowerCase() == 'none') {
					filters = Collections.emptyList()
				}
				else if (value.contains('JOINED_FILTERS')) {
					// special case to use either the filters defined by
					// conf.filterChain.filterNames or the filters defined by config settings;
					// can also remove one or more with a prefix of -
					def copy = new LinkedHashMap(allConfiguredFilters)
					for (item in value.split(',')) {
						item = item.toString().trim()
						if (item == 'JOINED_FILTERS') continue
						if (item.startsWith('-')) {
							item = item.substring(1)
							copy.remove(item)
						}
						else {
							throw new IllegalArgumentException("Cannot add a filter to JOINED_FILTERS, can only remove: $item")
						}
					}
					filters = new ArrayList(copy.values())
				}
				else {
					// explicit filter names
					filters = value.toString().split(',').collect { name -> ctx.getBean(name) }
				}
				filterChainMap[new AntPathRequestMatcher(key)] = filters
			}
		}
		else {
			filterChainMap[new AntPathRequestMatcher('/**')] = new ArrayList(allConfiguredFilters.values())
		}

		filterChain.filterChainMap = filterChainMap
		log.trace 'Filter chain: {}', filterChainMap

		// build voters list here to give dependent plugins a chance to register some
		def voterNames = conf.voterNames ?: SpringSecurityUtils.voterNames
		ctx.accessDecisionManager.decisionVoters = createBeanList(voterNames, ctx)
		log.trace 'AccessDecisionVoters: {}', ctx.accessDecisionManager.decisionVoters

		// build providers list here to give dependent plugins a chance to register some
		def providerNames = []
		if (conf.providerNames) {
			providerNames.addAll conf.providerNames
		}
		else {
			providerNames.addAll SpringSecurityUtils.providerNames
			if (conf.useX509) {
				providerNames << 'x509AuthenticationProvider'
			}
		}
		ctx.authenticationManager.providers = createBeanList(providerNames, ctx)
		log.trace 'AuthenticationProviders: {}', ctx.authenticationManager.providers

		// build handlers list here to give dependent plugins a chance to register some
		def logoutHandlerNames = (conf.logout.handlerNames ?: SpringSecurityUtils.logoutHandlerNames) +
			(conf.logout.additionalHandlerNames ?: [])
		ctx.logoutHandlers.clear()
		ctx.logoutHandlers.addAll createBeanList(logoutHandlerNames, ctx)
		log.trace 'LogoutHandlers: {}', ctx.logoutHandlers

		// build after-invocation provider names here to give dependent plugins a chance to register some
		def afterInvocationManagerProviderNames = conf.afterInvocationManagerProviderNames ?: SpringSecurityUtils.afterInvocationManagerProviderNames
		if (afterInvocationManagerProviderNames) {
			ctx.afterInvocationManager.providers = createBeanList(afterInvocationManagerProviderNames, ctx)
			log.trace 'AfterInvocationProviders: {}', ctx.afterInvocationManager.providers
		}

		if (conf.debug.useFilter) {
			ctx.removeAlias 'springSecurityFilterChain'
			ctx.registerAlias 'securityDebugFilter', 'springSecurityFilterChain'
		}

		if (conf.useDigestAuth) {
			def passwordEncoder = ctx.passwordEncoder
			if (passwordEncoder instanceof DigestAuthPasswordEncoder) {
				passwordEncoder.resetInitializing()
			}
		}
	}

	def onChange = { event ->

		def conf = SpringSecurityUtils.securityConfig
		if (!conf || !conf.active) {
			return
		}

		if (event.source && application.isControllerClass(event.source)) {

			log.trace 'onChange for controller {}', event.source.name

			if (SpringSecurityUtils.securityConfigType == 'Annotation') {
				initializeFromAnnotations event.ctx, conf, application
			}

			addControllerMethods application.getControllerClass(event.source.name).metaClass, event.ctx
		}
	}

	def onConfigChange = { event ->

		SpringSecurityUtils.resetSecurityConfig()

		def conf = SpringSecurityUtils.securityConfig
		if (!conf || !conf.active) {
			return
		}

		log.trace 'onConfigChange'

		if (SpringSecurityUtils.securityConfigType == 'Annotation') {
			// might have changed controllerAnnotations.staticRules
			initializeFromAnnotations event.ctx, conf, application
		}
		else if (SpringSecurityUtils.securityConfigType == 'InterceptUrlMap') {
			event.ctx.objectDefinitionSource.reset()
		}
	}

	private void initializeFromAnnotations(GrailsApplicationContext ctx, ConfigObject conf, GrailsApplication application) {
		AnnotationFilterInvocationDefinition afid = ctx.objectDefinitionSource
		afid.initialize conf.controllerAnnotations.staticRules,
			ctx.grailsUrlMappingsHolder, application.controllerClasses, application.domainClasses
	}

	private void addControllerMethods(MetaClass mc, ctx) {

		if (!mc.respondsTo(null, 'getPrincipal')) {
			mc.getPrincipal = { -> SCH.context?.authentication?.principal }
		}

		if (!mc.respondsTo(null, 'isLoggedIn')) {
			mc.isLoggedIn = { -> ctx.springSecurityService.isLoggedIn() }
		}

		if (!mc.respondsTo(null, 'getAuthenticatedUser')) {
			mc.getAuthenticatedUser = { ->
				if (!ctx.springSecurityService.isLoggedIn()) return null
				String userClassName = SpringSecurityUtils.securityConfig.userLookup.userDomainClassName
				def dc = ctx.grailsApplication.getDomainClass(userClassName)
				if (!dc) {
					throw new IllegalArgumentException("The specified user domain class '$userClassName' is not a domain class")
				}
				Class User = dc.clazz
				String usernamePropertyName = SpringSecurityUtils.securityConfig.userLookup.usernamePropertyName
				User.findWhere((usernamePropertyName): SCH.context.authentication.principal[usernamePropertyName])
			}
		}
	}

	private createRefList = { names -> names.collect { name -> ref(name) } }

	private createBeanList(names, ctx) { names.collect { name -> ctx.getBean(name) } }

	private configureLogout = { conf ->

		securityContextLogoutHandler(SecurityContextLogoutHandler) {
			clearAuthentication = conf.logout.clearAuthentication // true
			invalidateHttpSession = conf.logout.invalidateHttpSession // true
		}

		// create an initially empty list here, will be populated in doWithApplicationContext
		logoutHandlers(ArrayList)

		logoutSuccessHandler(SimpleUrlLogoutSuccessHandler) {
			redirectStrategy = ref('redirectStrategy')
			defaultTargetUrl = conf.logout.afterLogoutUrl // '/'
			alwaysUseDefaultTargetUrl = conf.logout.alwaysUseDefaultTargetUrl // false
			targetUrlParameter = conf.logout.targetUrlParameter // null
			useReferer = conf.logout.redirectToReferer // false
		}

		/** logoutFilter */
		logoutFilter(MutableLogoutFilter, ref('logoutSuccessHandler')) {
			filterProcessesUrl = conf.logout.filterProcessesUrl // '/j_spring_security_logout'
			handlers = ref('logoutHandlers')
		}
	}

	private configureBasicAuth = { conf ->

		basicAuthenticationEntryPoint(BasicAuthenticationEntryPoint) {
			realmName = conf.basic.realmName // 'Grails Realm'
		}

		basicAuthenticationFilter(BasicAuthenticationFilter, ref('authenticationManager'), ref('basicAuthenticationEntryPoint')) {
			authenticationDetailsSource = ref('authenticationDetailsSource')
			rememberMeServices = ref('rememberMeServices')
			credentialsCharset = conf.basic.credentialsCharset // 'UTF-8'
		}

		basicAccessDeniedHandler(AccessDeniedHandlerImpl)

		basicRequestCache(NullRequestCache)

		basicExceptionTranslationFilter(ExceptionTranslationFilter, ref('basicAuthenticationEntryPoint'), ref('basicRequestCache')) {
			accessDeniedHandler = ref('basicAccessDeniedHandler')
			authenticationTrustResolver = ref('authenticationTrustResolver')
			throwableAnalyzer = ref('throwableAnalyzer')
		}
	}

	private configureDigestAuth = { conf ->

		if (conf.digest.useCleartextPasswords) {
			passwordEncoder(PlaintextPasswordEncoder)
		}
		else {
			conf.digest.passwordAlreadyEncoded = true
			conf.dao.reflectionSaltSourceProperty = conf.userLookup.usernamePropertyName
			passwordEncoder(DigestAuthPasswordEncoder) {
				realm = conf.digest.realmName
			}
		}

		digestAuthenticationEntryPoint(DigestAuthenticationEntryPoint) {
			realmName = conf.digest.realmName // 'Grails Realm'
			key = conf.digest.key // 'changeme'
			nonceValiditySeconds = conf.digest.nonceValiditySeconds // 300
		}

		digestAuthenticationFilter(DigestAuthenticationFilter) {
			authenticationDetailsSource = ref('authenticationDetailsSource')
			authenticationEntryPoint = ref('digestAuthenticationEntryPoint')
			userCache = ref('userCache')
			userDetailsService = ref('userDetailsService')
			passwordAlreadyEncoded = conf.digest.passwordAlreadyEncoded // false
			createAuthenticatedToken = conf.digest.createAuthenticatedToken // false
		}

		digestAccessDeniedHandler(AccessDeniedHandlerImpl)

		digestExceptionTranslationFilter(ExceptionTranslationFilter, ref('digestAuthenticationEntryPoint'), ref('requestCache')) {
			accessDeniedHandler = ref('digestAccessDeniedHandler')
			authenticationTrustResolver = ref('authenticationTrustResolver')
			throwableAnalyzer = ref('throwableAnalyzer')
		}
	}

	private configureVoters = { conf ->

		roleHierarchy(RoleHierarchyImpl)

		roleVoter(RoleHierarchyVoter, ref('roleHierarchy'))

		authenticatedVoter(AuthenticatedVoter) {
			authenticationTrustResolver = ref('authenticationTrustResolver')
		}

		voterExpressionParser(SpelExpressionParser)

		// TODO set AuthenticationTrustResolver when exposed in 3.2
		webExpressionHandler(DefaultWebSecurityExpressionHandler) {
			roleHierarchy = ref('roleHierarchy')
			expressionParser = ref('voterExpressionParser')
			permissionEvaluator = ref('permissionEvaluator')
		}

		webExpressionVoter(WebExpressionVoter) {
			expressionHandler = ref('webExpressionHandler')
		}

		closureVoter(ClosureVoter)

		// create the default list here, will be replaced in doWithApplicationContext
		def voters = createRefList(SpringSecurityUtils.voterNames)

		/** accessDecisionManager */
		accessDecisionManager(AuthenticatedVetoableDecisionManager) {
			allowIfAllAbstainDecisions = false
			decisionVoters = voters
		}
	}

	private configureAuthenticationManager = { conf ->

		// create the default list here, will be replaced in doWithApplicationContext
		def providerRefs = createRefList(SpringSecurityUtils.providerNames)

		/** authenticationManager */
		authenticationManager(ProviderManager) {
			providers = providerRefs
			authenticationEventPublisher = ref('authenticationEventPublisher')
			eraseCredentialsAfterAuthentication = conf.providerManager.eraseCredentialsAfterAuthentication // true
		}
	}

	private configureFilterChain = { conf ->

		filterChainValidator(NullFilterChainValidator)

		httpFirewall(DefaultHttpFirewall)

		springSecurityFilterChainProxy(FilterChainProxy) {
			filterChainMap = [:] // will be set in doWithApplicationContext
			filterChainValidator = ref('filterChainValidator')
			firewall = ref('httpFirewall')
		}

		springConfig.addAlias 'springSecurityFilterChain', 'springSecurityFilterChainProxy'
	}

	private SortedMap<Integer, String> findFilterChainNames(conf) {

		SortedMap<Integer, String> orderedNames = new TreeMap()

		// if the user listed the names, use those
		def filterNames = conf.filterChain.filterNames
		if (filterNames) {
			// cheat and put them in the map in order - the key values don't
			// matter in this case since the user has chosen the order and
			// the map will be used to insert single filters, which wouldn't happen
			// if they've defined the order already
			filterNames.eachWithIndex { name, index -> orderedNames[index] = name }
		}
		else {

			orderedNames[SecurityFilterPosition.FIRST.order + 10] = 'securityRequestHolderFilter'

			if (conf.secureChannel.definition) {
				orderedNames[SecurityFilterPosition.CHANNEL_FILTER.order] = 'channelProcessingFilter'
			}

			// CONCURRENT_SESSION_FILTER

			orderedNames[SecurityFilterPosition.SECURITY_CONTEXT_FILTER.order] = 'securityContextPersistenceFilter'

			orderedNames[SecurityFilterPosition.LOGOUT_FILTER.order] = 'logoutFilter'

			if (conf.ipRestrictions) {
				orderedNames[SecurityFilterPosition.LOGOUT_FILTER.order + 1] = 'ipAddressFilter'
			}

			if (conf.useX509) {
				orderedNames[SecurityFilterPosition.X509_FILTER.order] = 'x509ProcessingFilter'
			}

			// PRE_AUTH_FILTER

			// CAS_FILTER

			orderedNames[SecurityFilterPosition.FORM_LOGIN_FILTER.order] = 'authenticationProcessingFilter'

			// OPENID_FILTER

			// facebook

			if (conf.useDigestAuth) {
				orderedNames[SecurityFilterPosition.DIGEST_AUTH_FILTER.order] = 'digestAuthenticationFilter'
				orderedNames[SecurityFilterPosition.EXCEPTION_TRANSLATION_FILTER.order + 1] = 'digestExceptionTranslationFilter'
			}

			if (conf.useBasicAuth) {
				orderedNames[SecurityFilterPosition.BASIC_AUTH_FILTER.order] = 'basicAuthenticationFilter'
				orderedNames[SecurityFilterPosition.EXCEPTION_TRANSLATION_FILTER.order + 1] = 'basicExceptionTranslationFilter'
			}

			// REQUEST_CACHE_FILTER

			orderedNames[SecurityFilterPosition.SERVLET_API_SUPPORT_FILTER.order] = 'securityContextHolderAwareRequestFilter'

			orderedNames[SecurityFilterPosition.REMEMBER_ME_FILTER.order] = 'rememberMeAuthenticationFilter'

			orderedNames[SecurityFilterPosition.ANONYMOUS_FILTER.order] = 'anonymousAuthenticationFilter'

			// SESSION_MANAGEMENT_FILTER

			orderedNames[SecurityFilterPosition.EXCEPTION_TRANSLATION_FILTER.order] = 'exceptionTranslationFilter'

			orderedNames[SecurityFilterPosition.FILTER_SECURITY_INTERCEPTOR.order] = 'filterInvocationInterceptor'

			if (conf.useSwitchUserFilter) {
				orderedNames[SecurityFilterPosition.SWITCH_USER_FILTER.order] = 'switchUserProcessingFilter'
			}

			// add in filters contributed by secondary plugins
			orderedNames.putAll SpringSecurityUtils.orderedFilters
		}

		orderedNames
	}

	private configureChannelProcessingFilter = { conf ->

		retryWithHttpEntryPoint(RetryWithHttpEntryPoint) {
			portMapper = ref('portMapper')
			portResolver = ref('portResolver')
			redirectStrategy = ref('redirectStrategy')
		}

		retryWithHttpsEntryPoint(RetryWithHttpsEntryPoint) {
			portMapper = ref('portMapper')
			portResolver = ref('portResolver')
			redirectStrategy = ref('redirectStrategy')
		}

		secureChannelProcessor(SecureChannelProcessor) {
			entryPoint = ref('retryWithHttpsEntryPoint')
		}

		insecureChannelProcessor(InsecureChannelProcessor) {
			entryPoint = ref('retryWithHttpEntryPoint')
		}

		channelDecisionManager(ChannelDecisionManagerImpl) {
			channelProcessors = [ref('insecureChannelProcessor'), ref('secureChannelProcessor')]
		}

		channelFilterInvocationSecurityMetadataSource(ChannelFilterInvocationSecurityMetadataSourceFactoryBean) {
			definition = conf.secureChannel.definition
		}
		channelProcessingFilter(ChannelProcessingFilter) {
			channelDecisionManager = ref('channelDecisionManager')
			securityMetadataSource = ref('channelFilterInvocationSecurityMetadataSource')
		}
	}

	private configureIpFilter = { conf ->
		ipAddressFilter(IpAddressFilter) {
			ipRestrictions = conf.ipRestrictions
		}
	}

	private configureAuthenticationProcessingFilter = { conf ->

		// TODO create plugin version that overrides extractAttributes
		if (conf.useSessionFixationPrevention) {
			log.trace 'Configuring session fixation prevention'
			sessionAuthenticationStrategy(SessionFixationProtectionStrategy) {
				migrateSessionAttributes = conf.sessionFixationPrevention.migrate // true
				alwaysCreateSession = conf.sessionFixationPrevention.alwaysCreateSession // false
			}
		}
		else {
			sessionAuthenticationStrategy(NullAuthenticatedSessionStrategy)
		}

		authenticationFailureHandler(AjaxAwareAuthenticationFailureHandler) {
			redirectStrategy = ref('redirectStrategy')
			defaultFailureUrl = conf.failureHandler.defaultFailureUrl //'/login/authfail?login_error=1'
			useForward = conf.failureHandler.useForward // false
			ajaxAuthenticationFailureUrl = conf.failureHandler.ajaxAuthFailUrl // '/login/authfail?ajax=true'
			exceptionMappings = conf.failureHandler.exceptionMappings // [:]
			allowSessionCreation = conf.failureHandler.allowSessionCreation // true
		}

		filterProcessUrlRequestMatcher(FilterProcessUrlRequestMatcher, conf.apf.filterProcessesUrl) // '/j_spring_security_check'

		authenticationProcessingFilter(GrailsUsernamePasswordAuthenticationFilter) {
			authenticationManager = ref('authenticationManager')
			sessionAuthenticationStrategy = ref('sessionAuthenticationStrategy')
			authenticationSuccessHandler = ref('authenticationSuccessHandler')
			authenticationFailureHandler = ref('authenticationFailureHandler')
			rememberMeServices = ref('rememberMeServices')
			authenticationDetailsSource = ref('authenticationDetailsSource')
			requiresAuthenticationRequestMatcher = ref('filterProcessUrlRequestMatcher')
			usernameParameter = conf.apf.usernameParameter // j_username
			passwordParameter = conf.apf.passwordParameter // j_password
			continueChainBeforeSuccessfulAuthentication = conf.apf.continueChainBeforeSuccessfulAuthentication // false
			allowSessionCreation = conf.apf.allowSessionCreation // true
			postOnly = conf.apf.postOnly // true
			storeLastUsername = conf.apf.storeLastUsername // false
		}

		authenticationDetailsSource(WebAuthenticationDetailsSource)

		requestMatcher(AnyRequestMatcher)

		requestCache(HttpSessionRequestCache) {
			portResolver = ref('portResolver')
			createSessionAllowed = conf.requestCache.createSession // true
			requestMatcher = ref('requestMatcher')
		}

		authenticationSuccessHandler(AjaxAwareAuthenticationSuccessHandler) {
			requestCache = ref('requestCache')
			defaultTargetUrl = conf.successHandler.defaultTargetUrl // '/'
			alwaysUseDefaultTargetUrl = conf.successHandler.alwaysUseDefault // false
			targetUrlParameter = conf.successHandler.targetUrlParameter // 'spring-security-redirect'
			ajaxSuccessUrl = conf.successHandler.ajaxSuccessUrl // '/login/ajaxSuccess'
			useReferer = conf.successHandler.useReferer // false
			redirectStrategy = ref('redirectStrategy')
		}

		redirectStrategy(GrailsRedirectStrategy) {
			useHeaderCheckChannelSecurity = conf.secureChannel.useHeaderCheckChannelSecurity // false
			portResolver = ref('portResolver')
		}
	}

	private configureX509 = { conf ->

		x509ProcessingFilter(X509AuthenticationFilter) {
			principalExtractor = ref('x509PrincipalExtractor')
			authenticationManager = ref('authenticationManager')
			authenticationDetailsSource = ref('authenticationDetailsSource')
			continueFilterChainOnUnsuccessfulAuthentication = conf.x509.continueFilterChainOnUnsuccessfulAuthentication // true
			checkForPrincipalChanges = conf.x509.checkForPrincipalChanges // false
			invalidateSessionOnPrincipalChange = conf.x509.invalidateSessionOnPrincipalChange // true
		}

		if (conf.x509.subjectDnClosure) {
			x509PrincipalExtractor(ClosureX509PrincipalExtractor)
		}
		else {
			x509PrincipalExtractor(SubjectDnX509PrincipalExtractor) {
				subjectDnRegex = conf.x509.subjectDnRegex // 'CN=(.*?)(?:,|$)'
			}
		}

		x509AuthenticationProvider(PreAuthenticatedAuthenticationProvider) {
			preAuthenticatedUserDetailsService = ref('authenticationUserDetailsService')
			userDetailsChecker = ref('userDetailsChecker')
			throwExceptionWhenTokenRejected = conf.x509.throwExceptionWhenTokenRejected // false
		}

		authenticationEntryPoint(Http403ForbiddenEntryPoint)
	}

	private findMappingLocation = { xml ->

		// find the location to insert the filter-mapping; needs to be after the 'charEncodingFilter'
		// which may not exist. should also be before the sitemesh filter.
		// thanks to the JSecurity plugin for the logic.

		def mappingLocation = xml.'filter-mapping'.find { it.'filter-name'.text() == 'charEncodingFilter' }
		if (mappingLocation) {
			return mappingLocation
		}

		// no 'charEncodingFilter'; try to put it before sitemesh
		int i = 0
		int siteMeshIndex = -1
		xml.'filter-mapping'.each {
			if (it.'filter-name'.text().equalsIgnoreCase('sitemesh')) {
				siteMeshIndex = i
			}
			i++
		}
		if (siteMeshIndex > 0) {
			return xml.'filter-mapping'[siteMeshIndex - 1]
		}

		if (siteMeshIndex == 0 || xml.'filter-mapping'.size() == 0) {
			def filters = xml.'filter'
			return filters[filters.size() - 1]
		}

		// neither filter found
		def filters = xml.'filter'
		return filters[filters.size() - 1]
	}
}
