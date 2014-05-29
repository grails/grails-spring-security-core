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
import grails.util.GrailsNameUtils

includeTargets << new File(springSecurityCorePluginDir, 'scripts/_S2Common.groovy')

USAGE = """
Usage: grails s2-quickstart <domain-class-package> <user-class-name> <role-class-name> [requestmap-class-name] [--groupClassName=group-class-name]
       or grails s2-quickstart --uiOnly

Creates a user and role class (and optionally a requestmap class) in the specified package.
If you specify a role-group name with the groupClassName argument, role/group classes will also be generated.
If you specify the uiOnly flag, no domain classes are created but the plugin settings are initialized (useful with LDAP, Mock, Shibboleth, etc.)

Example: grails s2-quickstart com.yourapp User Role
Example: grails s2-quickstart com.yourapp User Role --groupClassName=RoleGroup
Example: grails s2-quickstart com.yourapp Person Authority Requestmap
Example: grails s2-quickstart --uiOnly
"""

includeTargets << grailsScript('_GrailsBootstrap')

packageName = ''
userClassName = ''
roleClassName = ''
requestmapClassName = ''
groupClassName = ''
uiOnly = false

target(s2Quickstart: 'Creates artifacts for the Spring Security plugin') {
	depends(checkVersion, configureProxy, packageApp, classpath)

	if (!configure()) {
		return 1
	}

	if (!uiOnly) {
		createDomains()
	}
	updateConfig()

	if (uiOnly) {
		printMessage """
*******************************************************
* Your grails-app/conf/Config.groovy has been updated *
* with security settings; please verify that the      *
* values are correct.                                 *
*******************************************************
"""
	}
	else {
		printMessage """
*******************************************************
* Created security-related domain classes. Your       *
* grails-app/conf/Config.groovy has been updated with *
* the class names of the configured domain classes;   *
* please verify that the values are correct.          *
*******************************************************
"""
	}
}

private boolean configure() {

	def argValues = parseArgs()
	if (!argValues) {
		return false
	}

	if (argValues.size() == 4) {
		(packageName, userClassName, roleClassName, requestmapClassName) = argValues
	}
	else if (argValues.size() == 1 && argValues[0] == 'uiOnly') {
		uiOnly = true
		return true
	}
	else {
		(packageName, userClassName, roleClassName) = argValues
	}

	templateAttributes = [packageName: packageName,
	                      userClassName: userClassName,
	                      userClassProperty: GrailsNameUtils.getPropertyName(userClassName),
	                      roleClassName: roleClassName,
	                      roleClassProperty: GrailsNameUtils.getPropertyName(roleClassName),
	                      requestmapClassName: requestmapClassName,
	                      groupClassName: groupClassName,
	                      groupClassProperty: groupClassName ? GrailsNameUtils.getPropertyName(groupClassName) : null]

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
	if (groupClassName) {
		generateFile "$templateDir/AuthorityGroup.groovy.template", "$appDir/domain/${dir}${groupClassName}.groovy"
		generateFile "$templateDir/PersonAuthorityGroup.groovy.template", "$appDir/domain/${dir}${userClassName}${groupClassName}.groovy"
		generateFile "$templateDir/AuthorityGroupAuthority.groovy.template", "$appDir/domain/${dir}${groupClassName}${roleClassName}.groovy"
	}
}

private void updateConfig() {

	def configFile = new File(appDir, 'conf/Config.groovy')
	if (!configFile.exists()) {
		return
	}

	configFile.withWriterAppend { BufferedWriter writer ->
		writer.newLine()
		writer.newLine()
		writer.writeLine '// Added by the Spring Security Core plugin:'
		if (!uiOnly) {
			writer.writeLine "grails.plugin.springsecurity.userLookup.userDomainClassName = '${packageName}.$userClassName'"
			writer.writeLine "grails.plugin.springsecurity.userLookup.authorityJoinClassName = '${packageName}.$userClassName$roleClassName'"
			writer.writeLine "grails.plugin.springsecurity.authority.className = '${packageName}.$roleClassName'"
		}
		if (groupClassName) {
			writer.writeLine "grails.plugin.springsecurity.authority.groupAuthorityNameField = 'authorities'"
			writer.writeLine "grails.plugin.springsecurity.useRoleGroups = true"
		}
		if (requestmapClassName) {
			writer.writeLine "grails.plugin.springsecurity.requestMap.className = '${packageName}.$requestmapClassName'"
			writer.writeLine "grails.plugin.springsecurity.securityConfigType = 'Requestmap'"
		}
		writer.writeLine 'grails.plugin.springsecurity.controllerAnnotations.staticRules = ['
		writer.writeLine "\t'/':                              ['permitAll'],"
		writer.writeLine "\t'/index':                         ['permitAll'],"
		writer.writeLine "\t'/index.gsp':                     ['permitAll'],"
        writer.writeLine "\t'/assets/**':                     ['permitAll'],"
		writer.writeLine "\t'/**/js/**':                      ['permitAll'],"
		writer.writeLine "\t'/**/css/**':                     ['permitAll'],"
		writer.writeLine "\t'/**/images/**':                  ['permitAll'],"
		writer.writeLine "\t'/**/favicon.ico':                ['permitAll']"

		writer.writeLine ']'
		writer.newLine()
	}
}

private parseArgs() {

	if (argsMap.uiOnly) {
		printMessage 'Configuring Spring Security; not generating domain classes'
		return ['uiOnly']
	}

	def args = argsMap.params

	groupClassName = argsMap.groupClassName
	String groupClassNameMessage = groupClassName ? ", and role/group classes for $groupClassName" : ''

	if (3 == args.size()) {
		printMessage "Creating User class ${args[1]} and Role class ${args[2]}$groupClassNameMessage in package ${args[0]}"
		return args
	}

	if (4 == args.size()) {
		printMessage "Creating User class ${args[1]}, Role class ${args[2]}, and Requestmap class ${args[3]}$groupClassNameMessage in package ${args[0]}"
		return args
	}

	errorMessage USAGE
	null
}

setDefaultTarget 's2Quickstart'
