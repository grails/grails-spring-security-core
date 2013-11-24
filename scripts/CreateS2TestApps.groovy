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

includeTargets << new File(springSecurityCorePluginDir, "scripts/_S2Common.groovy")

projectfiles = new File(basedir, 'webtest/projectFiles')
grailsHome = null
grailsVersion = null
dotGrails = null
projectDir = null
appName = null
pluginVersion = null
testprojectRoot = null
deleteAll = false

target(createS2TestApp: 'Creates test apps for functional tests') {

	def configFile = new File(basedir, 'testapps.config.groovy')
	if (!configFile.exists()) {
		error "$configFile.path not found"
	}

	new ConfigSlurper().parse(configFile.text).each { name, config ->
		printMessage "\nCreating app based on configuration $name: ${config.flatten()}\n"
		init name, config
		createApp()
		installPlugins()
		runQuickstart()
		generateArtifacts()
		copySampleFiles()
		copyTests()
	}
}

private void callGrails(String grailsHome, String dir, String env, String action, List extraArgs = null, boolean ignoreFailure = false) {

	String resultproperty = 'exitCode' + System.currentTimeMillis()
	String outputproperty = 'execOutput' + System.currentTimeMillis()

	println "Running 'grails $env $action ${extraArgs?.join(' ') ?: ''}'"

	ant.exec(executable: "${grailsHome}/bin/grails", dir: dir, failonerror: false,
				resultproperty: resultproperty, outputproperty: outputproperty) {
		ant.env key: 'GRAILS_HOME', value: grailsHome
		ant.arg value: env
		ant.arg value: action
		extraArgs.each { ant.arg value: it }
		ant.arg value: '--stacktrace'
	}

	println ant.project.getProperty(outputproperty)

	int exitCode = ant.project.getProperty(resultproperty) as Integer
	if (exitCode && !ignoreFailure) {
		exit exitCode
	}
}

private void installPlugins() {

	File buildConfig = new File(testprojectRoot, 'grails-app/conf/BuildConfig.groovy')
	String contents = buildConfig.text

	contents = contents.replace('grails.project.class.dir = "target/classes"', "grails.project.work.dir = 'target'")
	contents = contents.replace('grails.project.test.class.dir = "target/test-classes"', '')
	contents = contents.replace('grails.project.test.reports.dir = "target/test-reports"', '')

	contents = contents.replace('//mavenLocal()', 'mavenLocal()')
	contents = contents.replace('repositories {', '''repositories {
mavenRepo 'http://repo.spring.io/milestone' // TODO remove
''')

	contents = contents.replace('grails.project.fork', 'grails.project.forkDISABLED')

	float grailsMinorVersion = grailsVersion[0..2] as float
	String spockDependency = grailsMinorVersion > 2.1 ? '		test "org.spockframework:spock-grails-support:0.7-groovy-2.0"' : ''
	String spockExclude = grailsMinorVersion > 2.1 ? '			exclude "spock-grails-support"' : ''

	contents = contents.replace('dependencies {', """
	String gebVersion = '0.9.2'
	String seleniumVersion = '2.32.0'

	dependencies {
		test "org.seleniumhq.selenium:selenium-chrome-driver:\$seleniumVersion"
		test "org.seleniumhq.selenium:selenium-firefox-driver:\$seleniumVersion"
		test 'com.github.detro.ghostdriver:phantomjsdriver:1.0.1', {
			transitive = false
		}
		test "org.gebish:geb-spock:\$gebVersion"
$spockDependency
""")

	contents = contents.replace('plugins {', """plugins {
		test "org.grails.plugins:geb:\$gebVersion"
		test ":spock:0.7", {
$spockExclude
		}

		runtime ":spring-security-core:$pluginVersion"
""")

	contents += '''

def file = new File('testconfig')
String testconfig = file.exists() ? file.text.trim() : ''
switch (testconfig) {
	case 'annotation':
		grails.testing.patterns = ['Role', 'User', 'AnnotationSecurity']
		break
	case 'basic':
		grails.testing.patterns = ['Role', 'User', 'BasicAuthSecurity']
		break
	case 'bcrypt':
		grails.testing.patterns = ['BCrypt']
		break
	case 'misc':
		grails.testing.patterns = ['Misc', 'Disable']
		break
	case 'requestmap':
		grails.testing.patterns = ['Requestmap', 'Role', 'User', 'RequestmapSecurity']
		break
	case 'static':
		grails.testing.patterns = ['Role', 'User', 'StaticSecurity']
		break
}'''

	String serverPort = '8' + grailsVersion.replaceAll('\\.', '')
	contents += """
grails.server.port.http = $serverPort"""

	buildConfig.withWriter { it.writeLine contents }

	callGrails grailsHome, testprojectRoot, 'dev', 'compile'
}

private void runQuickstart() {
	callGrails grailsHome, testprojectRoot, 'dev', 's2-quickstart', ['com.testapp', 'TestUser', 'TestRole', 'TestRequestmap']

	File user = new File(testprojectRoot, 'grails-app/domain/com/testapp/TestUser.groovy')
	String contents = user.text
	contents = contents.replace('springSecurityService.encodePassword(password)',
		'springSecurityService.encodePassword(password, springSecurityService.grailsApplication.config.grails.plugin.springsecurity.dao.reflectionSaltSourceProperty ? username : null)')

	user.withWriter { it.writeLine contents }

	File config = new File(testprojectRoot, 'grails-app/conf/Config.groovy')
	contents = config.text

	contents = contents.replace('grails.plugin.springsecurity.controllerAnnotations.staticRules = [', '''grails.plugin.springsecurity.controllerAnnotations.staticRules = [
	'/j_spring_security_switch_user': ['ROLE_ADMIN'],
	'/j_spring_security_exit_user':   ['permitAll'],''')

	contents += '''
grails.plugin.springsecurity.fii.rejectPublicInvocations = true
grails.plugin.springsecurity.rejectIfNoRule = false

grails.plugin.springsecurity.password.algorithm = 'SHA-256'

def file = new File('testconfig')
String testconfig = file.exists() ? file.text.trim() : ''
switch (testconfig) {
	case 'annotation':
		grails.plugin.springsecurity.securityConfigType = 'Annotation'
		break

	case 'basic':
		grails.plugin.springsecurity.securityConfigType = 'Annotation'
		grails.plugin.springsecurity.useBasicAuth = true
		grails.plugin.springsecurity.basic.realmName = 'Grails Spring Security Basic Test Realm'
		grails.plugin.springsecurity.filterChain.chainMap = [
			'/secureclassannotated/**': 'JOINED_FILTERS,-exceptionTranslationFilter',
			'/**': 'JOINED_FILTERS,-basicAuthenticationFilter,-basicExceptionTranslationFilter'
		]
		break

	case 'bcrypt':
		grails.plugin.springsecurity.securityConfigType = 'Annotation'
		grails.plugin.springsecurity.password.algorithm = 'bcrypt'
		break

	case 'misc':
		grails.plugin.springsecurity.securityConfigType = 'Annotation'
		grails.plugin.springsecurity.dao.reflectionSaltSourceProperty = 'username'
		grails.plugin.springsecurity.roleHierarchy = 'ROLE_ADMIN > ROLE_USER'
		grails.plugin.springsecurity.useSwitchUserFilter = true
		grails.plugin.springsecurity.failureHandler.exceptionMappings = [
			'org.springframework.security.authentication.LockedException':             '/testUser/accountLocked',
			'org.springframework.security.authentication.DisabledException':           '/testUser/accountDisabled',
			'org.springframework.security.authentication.AccountExpiredException':     '/testUser/accountExpired',
			'org.springframework.security.authentication.CredentialsExpiredException': '/testUser/passwordExpired'
		]
		grails.web.url.converter = 'hyphenated'
		break

	case 'requestmap':
		grails.plugin.springsecurity.securityConfigType = 'Requestmap'
		break

	case 'static':
		grails.plugin.springsecurity.securityConfigType = 'InterceptUrlMap'
		grails.plugin.springsecurity.interceptUrlMap = [
			'/secureannotated/admineither': ['ROLE_ADMIN', 'ROLE_ADMIN2'],
			'/secureannotated/expression': ["authentication.name == 'admin1'"],
			'/secureannotated/**': 'ROLE_ADMIN',
			'/**': 'IS_AUTHENTICATED_ANONYMOUSLY'
		]
		break
}'''

	config.withWriter { it.writeLine contents }

	File urlMappings = new File(testprojectRoot, 'grails-app/conf/UrlMappings.groovy')
	contents = urlMappings.text

	contents = contents.replace('''"500"(view:'/error')''', '''"500"(view:'/error')
		"401"(view:'/error401')
		"403"(view:'/error403')
''')

	urlMappings.withWriter { it.writeLine contents }
}

private void copySampleFiles() {

	ant.copy(todir: "$testprojectRoot/grails-app/controllers") {
		fileset(dir: projectfiles.path) {
			include name: 'FooBarController.groovy'
			include name: 'HackController.groovy'
			include name: 'LogoutController.groovy'
			include name: 'Secure*Controller.groovy'
			include name: 'TagLibTestController.groovy'
		}
	}

	ant.copy(todir: "$testprojectRoot/grails-app/views") {
		fileset(dir: projectfiles.path) {
			include name: 'error.gsp'
			include name: 'error401.gsp'
			include name: 'error403.gsp'
		}
	}

	ant.mkdir dir: "$testprojectRoot/grails-app/views/tagLibTest"
	ant.copy file: "${projectfiles.path}/test.gsp", todir: "$testprojectRoot/grails-app/views/tagLibTest"

	ant.mkdir dir: "$testprojectRoot/grails-app/views/logout"
	ant.copy file: "${projectfiles.path}/logout.index.gsp", tofile: "$testprojectRoot/grails-app/views/logout/index.gsp"

	ant.copy(todir: "$testprojectRoot/grails-app/services") {
		fileset(dir: projectfiles.path) {
			include name: '*Service.groovy'
		}
	}

	ant.mkdir dir: "$testprojectRoot/web-app/js/admin"
	ant.copy file: "${projectfiles.path}/admin.js", todir: "$testprojectRoot/web-app/js/admin"

	ant.copy file: "${projectfiles.path}/testproject-build.xml", tofile: "$testprojectRoot/build.xml"

	ant.copy(todir: "$testprojectRoot/grails-app/conf") {
		fileset(dir: projectfiles.path) {
			include name: 'BootStrap.groovy'
		}
	}

	String controllerDir = "$testprojectRoot/grails-app/controllers/com/testapp"
	ant.mkdir dir: controllerDir

	ant.copy file: "${projectfiles.path}/TestUserController_usingSalt_groovy", todir: controllerDir
	ant.copy file: "${projectfiles.path}/TestUserController_noSalt_groovy", todir: controllerDir
	ant.copy file: "${projectfiles.path}/TestRoleController.groovy", todir: controllerDir
	ant.copy file: "${projectfiles.path}/TestRequestmapController.groovy", todir: controllerDir

	ant.mkdir dir: "$testprojectRoot/grails-app/views/testUser"
	ant.copy(todir: "$testprojectRoot/grails-app/views/testUser") {
		fileset(dir: "$projectfiles.path/testUser")
	}
}

private void copyTests() {
	ant.copy(todir: "$testprojectRoot/test/functional") {
		fileset(dir: "$basedir/webtest/tests")
	}
}

private void generateArtifacts() {

	[testRole: 'com.testapp.TestRole', testRequestmap: 'com.testapp.TestRequestmap'].each { k, v ->

		callGrails grailsHome, testprojectRoot, 'dev', 'generate-views', [v]

		if (!new File(testprojectRoot, "grails-app/views/$k/list.gsp").exists()) {
			// Grails 2.3
			ant.copy file: "$testprojectRoot/grails-app/views/$k/index.gsp", tofile: "$testprojectRoot/grails-app/views/$k/list.gsp"
		}
	}

	// skip user, needs custom views
}

private void createApp() {

	ant.mkdir dir: projectDir

	deleteDir testprojectRoot
	deleteDir "$dotGrails/projects/$appName"

	callGrails grailsHome, projectDir, 'dev', 'create-app', [appName]
}

private void deleteDir(String path) {
	if (new File(path).exists() && !deleteAll) {
		String code = "confirm.delete.$path"
		ant.input message: "$path exists, ok to delete?", addproperty: code, validargs: 'y,n,a'
		def result = ant.antProject.properties[code]
		if ('a'.equalsIgnoreCase(result)) {
			deleteAll = true
		}
		else if (!'y'.equalsIgnoreCase(result)) {
			printMessage "\nNot deleting $path"
			exit 1
		}
	}

	ant.delete dir: path
}

private void init(String name, config) {

	pluginVersion = config.pluginVersion
	if (!pluginVersion) {
		error "pluginVersion wasn't specified for config '$name'"
	}

	def pluginZip = new File(basedir, "grails-spring-security-core-${pluginVersion}.zip")
	if (!pluginZip.exists()) {
//		error "plugin $pluginZip.absolutePath not found"
	}

	grailsHome = config.grailsHome
	if (!new File(grailsHome).exists()) {
		error "Grails home $grailsHome not found"
	}

	projectDir = config.projectDir
	appName = 'spring-security-core-test-' + name
	testprojectRoot = "$projectDir/$appName"

	grailsVersion = config.grailsVersion
	dotGrails = config.dotGrails + '/' + grailsVersion
}

private void error(String message) {
	errorMessage "\nERROR: $message"
	exit 1
}

setDefaultTarget 'createS2TestApp'
