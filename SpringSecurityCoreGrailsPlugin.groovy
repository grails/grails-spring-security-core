/* Copyright 2006-2012 the original author or authors.
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
import grails.plugins.springsecurity.BCryptPasswordEncoder
import grails.plugins.springsecurity.DigestAuthPasswordEncoder

import javax.servlet.Filter

import org.springframework.cache.ehcache.EhCacheFactoryBean
import org.springframework.cache.ehcache.EhCacheManagerFactoryBean
import org.springframework.security.access.event.LoggerListener
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl
import org.springframework.security.access.intercept.NullRunAsManager
import org.springframework.security.access.vote.AuthenticatedVoter
import org.springframework.security.access.vote.RoleHierarchyVoter
import org.springframework.security.authentication.AccountStatusUserDetailsChecker
import org.springframework.security.authentication.AnonymousAuthenticationProvider
import org.springframework.security.authentication.AuthenticationTrustResolverImpl
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher
import org.springframework.security.authentication.ProviderManager
import org.springframework.security.authentication.RememberMeAuthenticationProvider
import org.springframework.security.authentication.dao.DaoAuthenticationProvider
import org.springframework.security.authentication.dao.ReflectionSaltSource
import org.springframework.security.authentication.encoding.MessageDigestPasswordEncoder
import org.springframework.security.authentication.encoding.PlaintextPasswordEncoder
import org.springframework.security.core.context.SecurityContextHolder as SCH
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService
import org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper
import org.springframework.security.core.userdetails.cache.EhCacheBasedUserCache
import org.springframework.security.core.userdetails.cache.NullUserCache
import org.springframework.security.web.DefaultRedirectStrategy
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
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler
import org.springframework.security.web.authentication.rememberme.InMemoryTokenRepositoryImpl
import org.springframework.security.web.authentication.rememberme.PersistentTokenBasedRememberMeServices
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationFilter
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider
import org.springframework.security.web.authentication.preauth.x509.SubjectDnX509PrincipalExtractor
import org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy
import org.springframework.security.web.authentication.session.SessionFixationProtectionStrategy
import org.springframework.security.web.authentication.switchuser.SwitchUserFilter
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter
import org.springframework.security.web.authentication.www.DigestAuthenticationEntryPoint
import org.springframework.security.web.authentication.www.DigestAuthenticationFilter
import org.springframework.security.web.context.SecurityContextPersistenceFilter
import org.springframework.security.web.savedrequest.HttpSessionRequestCache
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter
import org.springframework.security.web.session.HttpSessionEventPublisher
import org.springframework.security.web.util.AntUrlPathMatcher
import org.springframework.security.web.util.RegexUrlPathMatcher
import org.springframework.web.filter.DelegatingFilterProxy

import org.codehaus.groovy.grails.plugins.springsecurity.AjaxAwareAccessDeniedHandler
import org.codehaus.groovy.grails.plugins.springsecurity.AjaxAwareAuthenticationEntryPoint
import org.codehaus.groovy.grails.plugins.springsecurity.AjaxAwareAuthenticationFailureHandler
import org.codehaus.groovy.grails.plugins.springsecurity.AjaxAwareAuthenticationSuccessHandler
import org.codehaus.groovy.grails.plugins.springsecurity.AnnotationFilterInvocationDefinition
import org.codehaus.groovy.grails.plugins.springsecurity.AuthenticatedVetoableDecisionManager
import org.codehaus.groovy.grails.plugins.springsecurity.DefaultPostAuthenticationChecks
import org.codehaus.groovy.grails.plugins.springsecurity.DefaultPreAuthenticationChecks
import org.codehaus.groovy.grails.plugins.springsecurity.ChannelFilterInvocationSecurityMetadataSourceFactoryBean
import org.codehaus.groovy.grails.plugins.springsecurity.GormPersistentTokenRepository
import org.codehaus.groovy.grails.plugins.springsecurity.GormUserDetailsService
import org.codehaus.groovy.grails.plugins.springsecurity.GrailsWebInvocationPrivilegeEvaluator
import org.codehaus.groovy.grails.plugins.springsecurity.HeaderCheckSecureChannelProcessor
import org.codehaus.groovy.grails.plugins.springsecurity.HeaderCheckInsecureChannelProcessor
import org.codehaus.groovy.grails.plugins.springsecurity.InterceptUrlMapFilterInvocationDefinition
import org.codehaus.groovy.grails.plugins.springsecurity.IpAddressFilter
import org.codehaus.groovy.grails.plugins.springsecurity.MutableLogoutFilter
import org.codehaus.groovy.grails.plugins.springsecurity.NullAuthenticationEventPublisher
import org.codehaus.groovy.grails.plugins.springsecurity.NullSaltSource
import org.codehaus.groovy.grails.plugins.springsecurity.RequestmapFilterInvocationDefinition
import org.codehaus.groovy.grails.plugins.springsecurity.RequestHolderAuthenticationFilter
import org.codehaus.groovy.grails.plugins.springsecurity.ReflectionUtils
import org.codehaus.groovy.grails.plugins.springsecurity.SecurityEventListener
import org.codehaus.groovy.grails.plugins.springsecurity.SecurityFilterPosition
import org.codehaus.groovy.grails.plugins.springsecurity.SecurityRequestHolder
import org.codehaus.groovy.grails.plugins.springsecurity.SpringSecurityUtils
import org.codehaus.groovy.grails.plugins.springsecurity.WebExpressionVoter

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class SpringSecurityCoreGrailsPlugin {

	String version = '1.2.7.3'
	String grailsVersion = '1.2.2 > *'
	List observe = ['controllers']
	List loadAfter = ['controllers', 'services', 'hibernate']

	List pluginExcludes = [
		'grails-app/domain/**',
		'scripts/CreateS2TestApps.groovy',
		'docs/**',
		'src/docs/**'
	]

	String author = 'Burt Beckwith'
	String authorEmail = 'beckwithb@vmware.com'
	String title = 'Spring Security Core Plugin'
	String description = 'Spring Security Core plugin'
	String documentation = 'http://grails.org/plugin/spring-security-core'

	String license = 'APACHE'
	def organization = [name: 'SpringSource', url: 'http://www.springsource.org/']
	def issueManagement = [system: 'JIRA', url: 'http://jira.grails.org/browse/GPSPRINGSECURITYCORE']
	def scm = [url: 'https://github.com/grails-plugins/grails-spring-security-core']

	// make sure the filter chain filter is after the Grails filter
	def getWebXmlFilterOrder() {
		def FilterManager = getClass().getClassLoader().loadClass('grails.plugin.webxml.FilterManager')
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

		// the name of the filter matches the name of the Spring bean that it delegates to
		contextParam[contextParam.size() - 1] + {
			'filter' {
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
				'dispatcher'('ERROR')
				'dispatcher'('REQUEST')
			}
		}

		if (conf.useHttpSessionEventPublisher) {
			def filterMapping = xml.'filter-mapping'
			filterMapping[filterMapping.size() - 1] + {
				'listener' {
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
		if (!conf || !conf.active) {
			println '\n\nSpring Security is disabled, not loading\n\n'
			return
		}

		println '\nConfiguring Spring Security Core ...'

		createRefList.delegate = delegate

		/** springSecurityFilterChain */
		configureFilterChain.delegate = delegate
		configureFilterChain conf

		// logout
		configureLogout.delegate = delegate
		configureLogout conf

		/** securityContextPersistenceFilter */
		securityContextPersistenceFilter(SecurityContextPersistenceFilter)

		/** authenticationProcessingFilter */
		configureAuthenticationProcessingFilter.delegate = delegate
		configureAuthenticationProcessingFilter conf

		/** securityContextHolderAwareRequestFilter */
		securityContextHolderAwareRequestFilter(SecurityContextHolderAwareRequestFilter)

		/** rememberMeAuthenticationFilter */
		rememberMeAuthenticationFilter(RememberMeAuthenticationFilter) {
			authenticationManager = ref('authenticationManager')
			rememberMeServices = ref('rememberMeServices')
		}

		/** rememberMeServices */
		if (conf.rememberMe.persistent) {
			rememberMeServices(PersistentTokenBasedRememberMeServices) {
				userDetailsService = ref('userDetailsService')
				key = conf.rememberMe.key
				cookieName = conf.rememberMe.cookieName
				alwaysRemember = conf.rememberMe.alwaysRemember
				tokenValiditySeconds = conf.rememberMe.tokenValiditySeconds
				parameter = conf.rememberMe.parameter
				useSecureCookie = conf.rememberMe.useSecureCookie // false

				tokenRepository = ref('tokenRepository')
				seriesLength = conf.rememberMe.persistentToken.seriesLength // 16
				tokenLength = conf.rememberMe.persistentToken.tokenLength // 16
			}

			tokenRepository(GormPersistentTokenRepository) {
				grailsApplication = ref('grailsApplication')
			}
		}
		else {
			rememberMeServices(TokenBasedRememberMeServices) {
				userDetailsService = ref('userDetailsService')
				key = conf.rememberMe.key
				cookieName = conf.rememberMe.cookieName
				alwaysRemember = conf.rememberMe.alwaysRemember
				tokenValiditySeconds = conf.rememberMe.tokenValiditySeconds
				parameter = conf.rememberMe.parameter
				useSecureCookie = conf.rememberMe.useSecureCookie // false
			}

			// register a lightweight impl so there's a bean in either case
			tokenRepository(InMemoryTokenRepositoryImpl)
		}

		/** anonymousAuthenticationFilter */
		anonymousAuthenticationFilter(AnonymousAuthenticationFilter) {
			key = conf.anon.key // 'foo'
			userAttribute = conf.anon.userAttribute //'anonymousUser,ROLE_ANONYMOUS'
		}

		/** exceptionTranslationFilter */
		exceptionTranslationFilter(ExceptionTranslationFilter) {
			authenticationEntryPoint = ref('authenticationEntryPoint')
			accessDeniedHandler = ref('accessDeniedHandler')
			authenticationTrustResolver = ref('authenticationTrustResolver')
			requestCache = ref('requestCache')
		}
		accessDeniedHandler(AjaxAwareAccessDeniedHandler) {
			errorPage = conf.adh.errorPage == 'null' ? null : conf.adh.errorPage // '/login/denied' or 403
			ajaxErrorPage = conf.adh.ajaxErrorPage
			portResolver = ref('portResolver')
			authenticationTrustResolver = ref('authenticationTrustResolver')
		}

		/** authenticationTrustResolver */
		authenticationTrustResolver(AuthenticationTrustResolverImpl) {
			anonymousClass = conf.atr.anonymousClass
			rememberMeClass = conf.atr.rememberMeClass
		}

		// default 'authenticationEntryPoint'
		authenticationEntryPoint(AjaxAwareAuthenticationEntryPoint) {
			loginFormUrl = conf.auth.loginFormUrl // '/login/auth'
			forceHttps = conf.auth.forceHttps // 'false'
			ajaxLoginFormUrl = conf.auth.ajaxLoginFormUrl // '/login/authAjax'
			useForward = conf.auth.useForward // false
			portMapper = ref('portMapper')
			portResolver = ref('portResolver')
		}

		/** filterInvocationInterceptor */
		filterInvocationInterceptor(FilterSecurityInterceptor) {
			authenticationManager = ref('authenticationManager')
			accessDecisionManager = ref('accessDecisionManager')
			securityMetadataSource = ref('objectDefinitionSource')
			runAsManager = ref('runAsManager')
		}

		String securityConfigType = SpringSecurityUtils.securityConfigType
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
				roleVoter = ref('roleVoter')
				authenticatedVoter = ref('authenticatedVoter')
				expressionHandler = ref('webExpressionHandler')
				boolean lowercase = conf.controllerAnnotations.lowercase // true
				if ('ant'.equals(conf.controllerAnnotations.matcher)) {
					urlMatcher = new AntUrlPathMatcher(lowercase)
				}
				else {
					urlMatcher = new RegexUrlPathMatcher(lowercase)
				}
				if (conf.rejectIfNoRule instanceof Boolean) {
					rejectIfNoRule = conf.rejectIfNoRule
				}
			}
		}
		else if (securityConfigType == 'Requestmap') {
			objectDefinitionSource(RequestmapFilterInvocationDefinition) {
				roleVoter = ref('roleVoter')
				authenticatedVoter = ref('authenticatedVoter')
				expressionHandler = ref('webExpressionHandler')
				urlMatcher = new AntUrlPathMatcher(true)
				if (conf.rejectIfNoRule instanceof Boolean) {
					rejectIfNoRule = conf.rejectIfNoRule
				}
			}
		}
		else if (securityConfigType == 'InterceptUrlMap') {
			objectDefinitionSource(InterceptUrlMapFilterInvocationDefinition) {
				roleVoter = ref('roleVoter')
				authenticatedVoter = ref('authenticatedVoter')
				expressionHandler = ref('webExpressionHandler')
				urlMatcher = new AntUrlPathMatcher(true)
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
		anonymousAuthenticationProvider(AnonymousAuthenticationProvider) {
			key = conf.anon.key // 'foo'
		}
		/** rememberMeAuthenticationProvider */
		rememberMeAuthenticationProvider(RememberMeAuthenticationProvider) {
			key = conf.rememberMe.key
		}

		// authenticationManager
		configureAuthenticationManager.delegate = delegate
		configureAuthenticationManager conf

		/** daoAuthenticationProvider */
		if (conf.dao.reflectionSaltSourceProperty) {
			saltSource(ReflectionSaltSource) {
				userPropertyToUse = conf.dao.reflectionSaltSourceProperty
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
			hideUserNotFoundExceptions = conf.dao.hideUserNotFoundExceptions // true
		}

		/** passwordEncoder */
		if (conf.password.algorithm == 'bcrypt') {
			passwordEncoder(BCryptPasswordEncoder)
		}
		else {
			passwordEncoder(MessageDigestPasswordEncoder, conf.password.algorithm) {
			if (conf.password.encodeHashAsBase64) {
					encodeHashAsBase64 = true
				}
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
			portMappings = [(conf.portMapper.httpPort.toString()) : conf.portMapper.httpsPort.toString()]
		}
		portResolver(PortResolverImpl) {
			portMapper = portMapper
		}

		// SecurityEventListener
		if (conf.useSecurityEventListener) {
			securityEventListener(SecurityEventListener)

			authenticationEventPublisher(DefaultAuthenticationEventPublisher)
		}
		else {
			authenticationEventPublisher(NullAuthenticationEventPublisher)
		}

		// Basic Auth
		if (conf.useBasicAuth) {
			configureBasicAuth.delegate = delegate
			configureBasicAuth conf
		}

		// Digest Auth
		if (conf.useDigestAuth) {
			configureDigestAuth.delegate = delegate
			configureDigestAuth conf
		}

		// Switch User
		if (conf.useSwitchUserFilter) {
			switchUserProcessingFilter(SwitchUserFilter) {
				userDetailsService = ref('userDetailsService')
				switchUserUrl = conf.switchUser.switchUserUrl // '/j_spring_security_switch_user'
				exitUserUrl = conf.switchUser.exitUserUrl // '/j_spring_security_exit_user'
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
			configureX509.delegate = delegate
			configureX509 conf
		}

		// channel (http/https) security
		if (conf.secureChannel.definition) {
			configureChannelProcessingFilter.delegate = delegate
			configureChannelProcessingFilter conf
		}

		// IP filter
		if (conf.ipRestrictions) {
			configureIpFilter.delegate = delegate
			configureIpFilter conf
		}

		// user details cache
		if (conf.cacheUsers) {
			userCache(EhCacheBasedUserCache) {
				cache = ref('securityUserCache')
			}
			securityUserCache(EhCacheFactoryBean) {
				cacheManager = ref('cacheManager')
				cacheName = 'userCache'
			}
			cacheManager(EhCacheManagerFactoryBean)
		}
		else {
			userCache(NullUserCache)
		}

		/** loggerListener */
		if (conf.registerLoggerListener) {
			loggerListener(LoggerListener)
		}

		println '... finished configuring Spring Security Core\n'
	}

	def doWithDynamicMethods = { ctx ->

		ReflectionUtils.application = application

		def conf = SpringSecurityUtils.securityConfig
		if (!conf || !conf.active) {
			return
		}

		for (controllerClass in application.controllerClasses) {
			addControllerMethods controllerClass.metaClass, ctx
		}

		if (SpringSecurityUtils.securityConfigType == 'Annotation') {
			ctx.objectDefinitionSource.initialize conf.controllerAnnotations.staticRules,
				ctx.grailsUrlMappingsHolder, application.controllerClasses
		}
	}

	def doWithApplicationContext = { ctx ->

		ReflectionUtils.application = application

		def conf = SpringSecurityUtils.securityConfig
		if (!conf || !conf.active) {
			return
		}

		// build filters here to give dependent plugins a chance to register some
		def filterChain = ctx.springSecurityFilterChain
		Map<String, List<Filter>> filterChainMap = [:]

		SortedMap<Integer, String> filterNames = findFilterChainNames(conf)
		def allConfiguredFilters = [:]
		filterNames.each { int order, String name ->
			def filter = ctx.getBean(name)
			allConfiguredFilters[name] = filter
			SpringSecurityUtils.getConfiguredOrderedFilters()[order] = filter
		}

		if (conf.filterChain.chainMap) {
			conf.filterChain.chainMap.each { key, value ->
				value = value.toString()
				def filters
				if (value.contains('JOINED_FILTERS')) {
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
							throw new RuntimeException("Cannot add a filter to JOINED_FILTERS, can only remove: $item")
						}
					}
					filters = new ArrayList(copy.values())
				}
				else {
					// explicit filter names
					filters = value.toString().split(',').collect { name -> ctx.getBean(name) }
				}
				filterChainMap[key] = filters
			}
		}
		else {
			filterChainMap[filterChain.matcher.universalMatchPattern] = new ArrayList(allConfiguredFilters.values()) // /**
		}

		filterChain.filterChainMap = filterChainMap

		// build voters list here to give dependent plugins a chance to register some
		def voterNames = conf.voterNames ?: SpringSecurityUtils.getVoterNames()
		ctx.accessDecisionManager.decisionVoters = createBeanList(voterNames, ctx)

		// build providers list here to give dependent plugins a chance to register some
		def providerNames = []
		if (conf.providerNames) {
			providerNames.addAll conf.providerNames
		}
		else {
			providerNames.addAll SpringSecurityUtils.getProviderNames()
			if (conf.useX509) {
				providerNames << 'x509AuthenticationProvider'
			}
		}
		ctx.authenticationManager.providers = createBeanList(providerNames, ctx)

		// build handlers list here to give dependent plugins a chance to register some
		def logoutHandlerNames = conf.logout.handlerNames ?: SpringSecurityUtils.LOGOUT_HANDLER_NAMES
		ctx.logoutHandlers.clear()
		ctx.logoutHandlers.addAll createBeanList(logoutHandlerNames, ctx)
	}

	def onChange = { event ->

		def conf = SpringSecurityUtils.securityConfig
		if (!conf || !conf.active) {
			return
		}

		if (event.source && application.isControllerClass(event.source)) {

			if (SpringSecurityUtils.securityConfigType == 'Annotation') {
				event.ctx.objectDefinitionSource.initialize conf.controllerAnnotations.staticRules,
					event.ctx.grailsUrlMappingsHolder, application.controllerClasses
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

		if (SpringSecurityUtils.securityConfigType == 'Annotation') {
			// might have changed controllerAnnotations.staticRules
			event.ctx.objectDefinitionSource.initialize conf.controllerAnnotations.staticRules,
				event.ctx.grailsUrlMappingsHolder, application.controllerClasses
		}
		else if (SpringSecurityUtils.securityConfigType == 'InterceptUrlMap') {
			event.ctx.objectDefinitionSource.reset()
		}
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
					throw new RuntimeException("The specified user domain class '$userClassName' is not a domain class")
				}
				Class User = dc.clazz
				User.get SCH.context.authentication.principal.id
			}
		}
	}

	private createRefList = { names -> names.collect { name -> ref(name) } }

	private createBeanList(names, ctx) { names.collect { name -> ctx.getBean(name) } }

	private configureLogout = { conf ->

		securityContextLogoutHandler(SecurityContextLogoutHandler)

		// create an initially empty list here, will be populated in doWithApplicationContext
		logoutHandlers(ArrayList)

		logoutSuccessHandler(SimpleUrlLogoutSuccessHandler) {
			redirectStrategy = ref('redirectStrategy')
			defaultTargetUrl = conf.logout.afterLogoutUrl // '/'
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

		basicAuthenticationFilter(BasicAuthenticationFilter) {
			authenticationManager = ref('authenticationManager')
			authenticationEntryPoint = ref('basicAuthenticationEntryPoint')
		}

		basicAccessDeniedHandler(AccessDeniedHandlerImpl)

		basicExceptionTranslationFilter(ExceptionTranslationFilter) {
			accessDeniedHandler = ref('basicAccessDeniedHandler')
			authenticationTrustResolver = ref('authenticationTrustResolver')
			requestCache = ref('requestCache')
			authenticationEntryPoint = ref('basicAuthenticationEntryPoint')
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

		digestExceptionTranslationFilter(ExceptionTranslationFilter) {
			accessDeniedHandler = ref('digestAccessDeniedHandler')
			authenticationTrustResolver = ref('authenticationTrustResolver')
			requestCache = ref('requestCache')
			authenticationEntryPoint = ref('digestAuthenticationEntryPoint')
		}
	}

	private configureVoters = { conf ->

		roleHierarchy(RoleHierarchyImpl) {
			hierarchy = conf.roleHierarchy
		}

		roleVoter(RoleHierarchyVoter, ref('roleHierarchy'))

		authenticatedVoter(AuthenticatedVoter) {
			authenticationTrustResolver = ref('authenticationTrustResolver')
		}

		webExpressionHandler(DefaultWebSecurityExpressionHandler) {
			roleHierarchy = ref('roleHierarchy')
		}

		webExpressionVoter(WebExpressionVoter) {
			expressionHandler = ref('webExpressionHandler')
		}

		// create the default list here, will be replaced in doWithApplicationContext
		def voters = createRefList(SpringSecurityUtils.getVoterNames())

		/** accessDecisionManager */
		accessDecisionManager(AuthenticatedVetoableDecisionManager) {
			allowIfAllAbstainDecisions = false
			decisionVoters = voters
		}
	}

	private configureAuthenticationManager = { conf ->

		// create the default list here, will be replaced in doWithApplicationContext
		def providerRefs = createRefList(SpringSecurityUtils.getProviderNames())

		/** authenticationManager */
		authenticationManager(ProviderManager) {
			providers = providerRefs
			authenticationEventPublisher = ref('authenticationEventPublisher')
			eraseCredentialsAfterAuthentication = conf.providerManager.eraseCredentialsAfterAuthentication // false
		}
	}

	private configureFilterChain = { conf ->
		springSecurityFilterChain(FilterChainProxy) {
			filterChainMap = [:] // will be set in doWithApplicationContext
			stripQueryStringFromUrls = conf.filterChain.stripQueryStringFromUrls // true
			matcher = new AntUrlPathMatcher(true) // make into bean
		}
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
			orderedNames.putAll SpringSecurityUtils.getOrderedFilters()
		}

		orderedNames
	}

	private configureChannelProcessingFilter = { conf ->

		retryWithHttpEntryPoint(RetryWithHttpEntryPoint) {
			portMapper = ref('portMapper')
			portResolver = ref('portResolver')
		}

		retryWithHttpsEntryPoint(RetryWithHttpsEntryPoint) {
			portMapper = ref('portMapper')
			portResolver = ref('portResolver')
		}

		if (conf.secureChannel.useHeaderCheckChannelSecurity) {
			secureChannelProcessor(HeaderCheckSecureChannelProcessor) {
				entryPoint = ref('retryWithHttpsEntryPoint')
				headerName = conf.secureChannel.secureHeaderName // 'X-Forwarded-Proto'
				headerValue = conf.secureChannel.secureHeaderValue // 'http'
			}

			insecureChannelProcessor(HeaderCheckInsecureChannelProcessor) {
				entryPoint = ref('retryWithHttpEntryPoint')
				headerName = conf.secureChannel.insecureHeaderName // 'X-Forwarded-Proto'
				headerValue = conf.secureChannel.insecureHeaderValue // 'https'
			}
		}
		else {
			secureChannelProcessor(SecureChannelProcessor) {
				entryPoint = ref('retryWithHttpsEntryPoint')
			}

			insecureChannelProcessor(InsecureChannelProcessor) {
				entryPoint = ref('retryWithHttpEntryPoint')
			}
		}

		channelDecisionManager(ChannelDecisionManagerImpl) {
			channelProcessors = [ref('insecureChannelProcessor'), ref('secureChannelProcessor')]
		}

		channelFilterInvocationSecurityMetadataSource(ChannelFilterInvocationSecurityMetadataSourceFactoryBean) {
			urlMatcher = new AntUrlPathMatcher(true)
			definition = conf.secureChannel.definition
		}
		channelProcessingFilter(ChannelProcessingFilter) {
			channelDecisionManager = channelDecisionManager
			securityMetadataSource = channelFilterInvocationSecurityMetadataSource
		}
	}

	private configureIpFilter = { conf ->
		ipAddressFilter(IpAddressFilter) {
			ipRestrictions = conf.ipRestrictions
		}
	}

	private configureAuthenticationProcessingFilter = { conf ->

		if (conf.useSessionFixationPrevention) {
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
		}

		authenticationProcessingFilter(RequestHolderAuthenticationFilter) {
			authenticationManager = ref('authenticationManager')
			sessionAuthenticationStrategy = ref('sessionAuthenticationStrategy')
			authenticationSuccessHandler = ref('authenticationSuccessHandler')
			authenticationFailureHandler = ref('authenticationFailureHandler')
			rememberMeServices = ref('rememberMeServices')
			authenticationDetailsSource = ref('authenticationDetailsSource')
			filterProcessesUrl = conf.apf.filterProcessesUrl // '/j_spring_security_check'
			usernameParameter = conf.apf.usernameParameter // j_username
			passwordParameter = conf.apf.passwordParameter // j_password
			continueChainBeforeSuccessfulAuthentication = conf.apf.continueChainBeforeSuccessfulAuthentication // false
			allowSessionCreation = conf.apf.allowSessionCreation // true
			postOnly = conf.apf.postOnly // true
		}

		authenticationDetailsSource(WebAuthenticationDetailsSource) {
			clazz = conf.authenticationDetails.authClass // WebAuthenticationDetails
		}

		requestCache(HttpSessionRequestCache) {
			portResolver = ref('portResolver')
			justUseSavedRequestOnGet = conf.requestCache.onlyOnGet // false
			createSessionAllowed = conf.requestCache.createSession // true
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

		redirectStrategy(DefaultRedirectStrategy) {
			contextRelative = conf.redirectStrategy.contextRelative // false
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

		x509PrincipalExtractor(SubjectDnX509PrincipalExtractor) {
			subjectDnRegex = conf.x509.subjectDnRegex // CN=(.*?),
		}

		userDetailsChecker(AccountStatusUserDetailsChecker)

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
