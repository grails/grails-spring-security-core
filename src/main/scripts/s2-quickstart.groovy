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

import grails.codegen.model.Model
import groovy.transform.Field

@Field String usageMessage = '''
   grails s2-quickstart <domain-class-package> <user-class-name> <role-class-name> [requestmap-class-name] [--groupClassName=group-class-name]
or grails s2-quickstart --uiOnly

Example: grails s2-quickstart com.yourapp User Role
Example: grails s2-quickstart com.yourapp User Role --groupClassName=RoleGroup
Example: grails s2-quickstart com.yourapp Person Authority Requestmap
Example: grails s2-quickstart --uiOnly
'''

@Field Map templateAttributes
@Field boolean uiOnly

description 'Creates domain classes and updates config settings for the Spring Security plugin', {

	usage usageMessage

	argument name: 'Domain class package',  description: 'The package to use for the domain classes', required: false
	argument name: 'User class name',       description: 'The name of the User/Person class',         required: false
	argument name: 'Role class name',       description: 'The name of the Role class',                required: false
	argument name: 'Requestmap class name', description: 'The name of the Requestmap class',          required: false

	flag name: 'groupClassName', description: 'If specified, role/group classes will also be generated using the flag value as the role-group name'
	flag name: 'uiOnly', description: 'If specified, no domain classes are created but the plugin settings are initialized (useful with LDAP, Mock, Shibboleth, etc.)'
}

Model userModel
Model roleModel
Model requestmapModel
Model groupModel
uiOnly = flag('uiOnly')
if (uiOnly) {
	addStatus '\nConfiguring Spring Security; not generating domain classes'
}
else {

	if (args.size() < 3) {
		error 'Usage:' + usageMessage
		return false
	}

	String packageName = args[0]
	String groupClassName = flag('groupClassName')
	String groupClassNameMessage = ''
	if (groupClassName) {
		groupModel = model(packageName + '.' + groupClassName)
		groupClassNameMessage = ", and role/group classes for '" + groupModel.simpleName + "'"
	}

	userModel = model(packageName + '.' + args[1])
	roleModel = model(packageName + '.' + args[2])

	String message = "Creating User class '" + userModel.simpleName + "'"
	if (4 == args.size()) {
		requestmapModel = model(packageName + '.' + args[3])
		message += ", Role class '" + roleModel.simpleName + "', and Requestmap class '" + requestmapModel.simpleName + "'" + groupClassNameMessage
	}
	else {
		message += " and Role class '" + roleModel.simpleName + "'" + groupClassNameMessage
	}
	message += " in package '" + packageName + "'"
	addStatus message

	templateAttributes = [
		packageName: userModel.packageName,
		userClassName: userModel.simpleName,
		userClassProperty: userModel.modelName,
		roleClassName: roleModel.simpleName,
		roleClassProperty: roleModel.modelName,
		requestmapClassName: requestmapModel?.simpleName,
		groupClassName: groupModel?.simpleName,
		groupClassProperty: groupModel?.modelName]

	createDomains userModel, roleModel, requestmapModel, groupModel
}

updateConfig userModel?.simpleName, roleModel?.simpleName, requestmapModel?.simpleName, userModel?.packageName, groupModel != null

if (uiOnly) {
	addStatus '''
************************************************************
* Your grails-app/conf/application.groovy has been updated *
* with security settings; please verify that the           *
* values are correct.                                      *
************************************************************
'''
}
else {
	addStatus '''
************************************************************
* Created security-related domain classes. Your            *
* grails-app/conf/application.groovy has been updated with *
* the class names of the configured domain classes;        *
* please verify that the values are correct.               *
************************************************************
'''
}

private void createDomains(Model userModel, Model roleModel, Model requestmapModel, Model groupModel) {

	generateFile 'Person', userModel.packagePath, userModel.simpleName
	generateFile 'Authority', roleModel.packagePath, roleModel.simpleName
	generateFile 'PersonAuthority', roleModel.packagePath, userModel.simpleName + roleModel.simpleName

	if (requestmapModel) {
		generateFile 'Requestmap', requestmapModel.packagePath, requestmapModel.simpleName
	}

	if (groupModel) {
		generateFile 'AuthorityGroup', groupModel.packagePath, groupModel.simpleName
		generateFile 'PersonAuthorityGroup', groupModel.packagePath, userModel.simpleName + groupModel.simpleName
		generateFile 'AuthorityGroupAuthority', groupModel.packagePath, groupModel.simpleName + roleModel.simpleName
	}
}

private void updateConfig(String userClassName, String roleClassName, String requestmapClassName, String packageName, boolean useRoleGroups) {

	file('grails-app/conf/application.groovy').withWriterAppend { BufferedWriter writer ->
		writer.newLine()
		writer.newLine()
		writer.writeLine '// Added by the Spring Security Core plugin:'
		if (!uiOnly) {
			writer.writeLine "grails.plugin.springsecurity.userLookup.userDomainClassName = '${packageName}.$userClassName'"
			writer.writeLine "grails.plugin.springsecurity.userLookup.authorityJoinClassName = '${packageName}.$userClassName$roleClassName'"
			writer.writeLine "grails.plugin.springsecurity.authority.className = '${packageName}.$roleClassName'"
		}
		if (useRoleGroups) {
			writer.writeLine "grails.plugin.springsecurity.authority.groupAuthorityNameField = 'authorities'"
			writer.writeLine 'grails.plugin.springsecurity.useRoleGroups = true'
		}
		if (requestmapClassName) {
			writer.writeLine "grails.plugin.springsecurity.requestMap.className = '${packageName}.$requestmapClassName'"
			writer.writeLine "grails.plugin.springsecurity.securityConfigType = 'Requestmap'"
		}
		writer.writeLine 'grails.plugin.springsecurity.controllerAnnotations.staticRules = ['
		writer.writeLine "\t'/':                ['permitAll'],"
		writer.writeLine "\t'/error':           ['permitAll'],"
		writer.writeLine "\t'/index':           ['permitAll'],"
		writer.writeLine "\t'/index.gsp':       ['permitAll'],"
		writer.writeLine "\t'/shutdown':        ['permitAll'],"
		writer.writeLine "\t'/assets/**':       ['permitAll'],"
		writer.writeLine "\t'/**/js/**':        ['permitAll'],"
		writer.writeLine "\t'/**/css/**':       ['permitAll'],"
		writer.writeLine "\t'/**/images/**':    ['permitAll'],"
		writer.writeLine "\t'/**/favicon.ico':  ['permitAll']"

		writer.writeLine ']'
		writer.newLine()
	}
}

private void generateFile(String templateName, String packagePath, String className) {
	render template(templateName + '.groovy.template'),
	       file("grails-app/domain/$packagePath/${className}.groovy"),
	       templateAttributes, false
}
