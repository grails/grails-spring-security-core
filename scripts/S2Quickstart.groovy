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
import grails.util.GrailsNameUtils
import grails.util.Metadata

includeTargets << new File("$springSecurityCorePluginDir/scripts/_S2Common.groovy")

USAGE = """
Usage: grails s2-quickstart <domain-class-package> <user-class-name> <role-class-name> [requestmap-class-name]

Creates a user and role class (and optionally a requestmap class) in the specified package

Example: grails s2-quickstart com.yourapp User Role
Example: grails s2-quickstart com.yourapp Person Authority Requestmap
"""

includeTargets << grailsScript('_GrailsBootstrap')

packageName = ''
userClassName = ''
roleClassName = ''
requestmapClassName = ''

target(s2Quickstart: 'Creates artifacts for the Spring Security plugin') {
	depends(checkVersion, configureProxy, packageApp, classpath)

	if (!configure()) {
		return 1
	}
	createDomains()
	copyControllersAndViews()
	updateConfig()

	printMessage """
*******************************************************
* Created domain classes, controllers, and GSPs. Your *
* grails-app/conf/Config.groovy has been updated with *
* the class names of the configured domain classes;   *
* please verify that the values are correct.          *
*******************************************************
"""
}

private boolean configure() {

	def argValues = parseArgs()
	if (!argValues) {
		return false
	}

	if (argValues.size() == 4) {
		(packageName, userClassName, roleClassName, requestmapClassName) = argValues
	}
	else {
		(packageName, userClassName, roleClassName) = argValues
	}

	templateAttributes = [packageName: packageName,
	                      userClassName: userClassName,
	                      userClassProperty: GrailsNameUtils.getPropertyName(userClassName),
	                      roleClassName: roleClassName,
	                      roleClassProperty: GrailsNameUtils.getPropertyName(roleClassName),
	                      requestmapClassName: requestmapClassName]

	if (Metadata.current.getGrailsVersion().startsWith('1.2')) {
		templateAttributes.dependencyInjections = '''\
	transient springSecurityService
	transient grailsApplication
	transient sessionFactory
'''
		templateAttributes.dirtyMethods = '''

	private boolean isDirty(String fieldName) {
		def session = sessionFactory.currentSession
		def entry = findEntityEntry(session)
		if (!entry) {
			return false
		}

		Object[] values = entry.persister.getPropertyValues(this, session.entityMode)
		int[] dirtyProperties = entry.persister.findDirty(values, entry.loadedState, this, session)
		int fieldIndex = entry.persister.propertyNames.findIndexOf { fieldName == it }
		return fieldIndex in dirtyProperties
	}

	private findEntityEntry(session) {
		def entry = session.persistenceContext.getEntry(this)
		if (!entry) {
			return null
		}

		if (!entry.requiresDirtyCheck(this) && entry.loadedState) {
			return null
		}

		entry
	}'''
	}
	else {
		templateAttributes.dependencyInjections = '''\
	transient springSecurityService
'''
		templateAttributes.dirtyMethods = ''
	}

	true
}

private void createDomains() {

	String dir = packageToDir(packageName)
	generateFile "$templateDir/Person.groovy.template", "$appDir/domain/${dir}${userClassName}.groovy"
	generateFile "$templateDir/Authority.groovy.template", "$appDir/domain/${dir}${roleClassName}.groovy"
	generateFile "$templateDir/PersonAuthority.groovy.template", "$appDir/domain/${dir}${userClassName}${roleClassName}.groovy"
	if (requestmapClassName) {
		generateFile "$templateDir/Requestmap.groovy.template", "$appDir/domain/${dir}${requestmapClassName}.groovy"
	}
}

private void copyControllersAndViews() {
	ant.mkdir dir: "$appDir/views/login"
	copyFile "$templateDir/auth.gsp.template", "$appDir/views/login/auth.gsp"
	copyFile "$templateDir/denied.gsp.template", "$appDir/views/login/denied.gsp"
	copyFile "$templateDir/LoginController.groovy.template", "$appDir/controllers/LoginController.groovy"
	copyFile "$templateDir/LogoutController.groovy.template", "$appDir/controllers/LogoutController.groovy"
}

private void updateConfig() {

	def configFile = new File(appDir, 'conf/Config.groovy')
	if (configFile.exists()) {
		configFile.withWriterAppend {
			it.writeLine '\n// Added by the Spring Security Core plugin:'
			it.writeLine "grails.plugins.springsecurity.userLookup.userDomainClassName = '${packageName}.$userClassName'"
			it.writeLine "grails.plugins.springsecurity.userLookup.authorityJoinClassName = '${packageName}.$userClassName$roleClassName'"
			it.writeLine "grails.plugins.springsecurity.authority.className = '${packageName}.$roleClassName'"
			if (requestmapClassName) {
				it.writeLine "grails.plugins.springsecurity.requestMap.className = '${packageName}.$requestmapClassName'"
				it.writeLine "grails.plugins.springsecurity.securityConfigType = 'Requestmap'"
			}
		}
	}
}

private parseArgs() {
	def args = argsMap.params

	if (3 == args.size()) {
		printMessage "Creating User class ${args[1]} and Role class ${args[2]} in package ${args[0]}"
		return args
	}

	if (4 == args.size()) {
		printMessage "Creating User class ${args[1]}, Role class ${args[2]}, and Requestmap class ${args[3]} in package ${args[0]}"
		return args
	}

	errorMessage USAGE
	null
}

setDefaultTarget 's2Quickstart'
