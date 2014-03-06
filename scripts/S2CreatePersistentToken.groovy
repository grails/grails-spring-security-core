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

includeTargets << new File(springSecurityCorePluginDir, 'scripts/_S2Common.groovy')

fullClassName = null

USAGE = """
	Usage: grails s2-create-persistent-token <domain-class-name>

	Creates a persistent token domain class

	Example: grails s2-create-persistent-token com.yourapp.PersistentLogin
"""

target(s2CreatePersistentToken: 'Creates the persistent token domain class for the Spring Security Core plugin') {
	depends(checkVersion, configureProxy, packageApp, classpath)

	if (!configure()) {
		return
	}
	createDomainClass()
	updateConfig()
}

private boolean configure() {

	fullClassName = parseArgs()
	if (!fullClassName) {
		return false
	}

	String packageName
	String className
	(packageName, className) = splitClassName(fullClassName)

	String packageDeclaration = ''
	if (packageName) {
		packageDeclaration = "package $packageName"
	}

	templateAttributes = [packageName: packageName,
	                      packageDeclaration: packageDeclaration,
	                      className: className]

	true
}

private void createDomainClass() {
	String dir = packageToDir(templateAttributes.packageName)
	generateFile "$templateDir/PersistentLogin.groovy.template",
	             "$appDir/domain/${dir}${templateAttributes.className}.groovy"
}

private void updateConfig() {
	def configFile = new File(appDir, 'conf/Config.groovy')
	if (!configFile.exists()) {
		return
	}

	configFile.withWriterAppend { BufferedWriter writer ->
		writer.writeLine "grails.plugin.springsecurity.rememberMe.persistent = true"
		writer.writeLine "grails.plugin.springsecurity.rememberMe.persistentToken.domainClassName = '$fullClassName'"
		writer.newLine()
	}
}

private parseArgs() {
	def args = argsMap.params

	if (1 == args.size()) {
		printMessage "Creating persistent token class ${args[0]}"
		return args[0]
	}

	errorMessage USAGE
	null
}

setDefaultTarget 's2CreatePersistentToken'
