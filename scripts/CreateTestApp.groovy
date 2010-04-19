includeTargets << grailsScript('_GrailsBootstrap')

functionalTestPluginVersion = '1.2.7'
projectfiles = new File(basedir, 'webtest/projectFiles')
grailsHome = null
dotGrails = null
projectDir = null
appName = null
pluginVersion = null
pluginZip = null
testprojectRoot = null

target(createTestApp: 'Creates test apps for functional tests') {

	def configFile = new File(basedir, 'testapps.config.groovy')
	if (!configFile.exists()) {
		error "$configFile.path not found"
	}

	new ConfigSlurper().parse(configFile.text).each { name, config ->
		echo "\nCreating app based on configuration $name: ${config.flatten()}\n"
		init name, config
		createApp()
		installPlugins()
		runQuickstart()
		generateArtifacts()
		copySampleFiles()
		copyTests()
	}
}

private void callGrails(String grailsHome, String dir, String env, String action, extraArgs = null) {
	ant.exec(executable: "${grailsHome}/bin/grails", dir: dir, failonerror: 'true') {
		ant.env key: 'GRAILS_HOME', value: grailsHome
		ant.arg value: env
		ant.arg value: action
		extraArgs?.call()
	}
}

private void installPlugins() {

	// install plugins in local dir to make optional STS setup easier
	new File("$testprojectRoot/grails-app/conf/BuildConfig.groovy").withWriterAppend {
		it.writeLine 'grails.project.plugins.dir = "plugins"'
	}

	ant.mkdir dir: "${testprojectRoot}/plugins"
	callGrails(grailsHome, testprojectRoot, 'dev', 'install-plugin') {
		ant.arg value: "functional-test ${functionalTestPluginVersion}"
	}
	callGrails(grailsHome, testprojectRoot, 'dev', 'install-plugin') {
		ant.arg value: pluginZip.absolutePath
	}
}

private void runQuickstart() {
	callGrails(grailsHome, testprojectRoot, 'dev', 's2-quickstart') {
		ant.arg value: 'com.testapp'
		ant.arg value: 'TestUser TestRole TestRequestmap'
	}
}

private void copySampleFiles() {

	ant.copy(todir: "${testprojectRoot}/grails-app/controllers") {
		fileset(dir: projectfiles.path) {
			include name: 'Secure*Controller.groovy'
			include name: 'HackController.groovy'
		}
	}

	ant.copy(todir: "${testprojectRoot}/grails-app/services") {
		fileset(dir: projectfiles.path) {
			include name: '*Service.groovy'
		}
	}

	ant.mkdir dir: "${testprojectRoot}/web-app/js/admin"
	ant.copy file: "${projectfiles.path}/admin.js", todir: "${testprojectRoot}/web-app/js/admin"

	ant.copy file: "${projectfiles.path}/testproject-build.xml", tofile: "${testprojectRoot}/build.xml"

	ant.copy(todir: "${testprojectRoot}/grails-app/conf") {
		fileset(dir: projectfiles.path) {
			include name: 'SecurityConfig-*_groovy'
		}
	}

	String controllerDir = "${testprojectRoot}/grails-app/controllers/com/testapp"
	ant.mkdir dir: controllerDir

	ant.copy file: "${projectfiles.path}/TestUserController_usingSalt_groovy", todir: controllerDir
	ant.copy file: "${projectfiles.path}/TestUserController_noSalt_groovy", todir: controllerDir
	ant.copy file: "${projectfiles.path}/TestRoleController.groovy", todir: controllerDir
	ant.copy file: "${projectfiles.path}/TestRequestmapController.groovy", todir: controllerDir

	ant.mkdir dir: "${testprojectRoot}/grails-app/views/testUser"
	ant.copy(todir: "${testprojectRoot}/grails-app/views/testUser") {
		fileset(dir: "$projectfiles.path/testUser")
	}
}

private void copyTests() {

	ant.copy(todir: "${testprojectRoot}/test/functional") {
		fileset(dir: "$basedir/webtest/tests")
	}

	ant.copy file: "${projectfiles.path}/FuncTest.groovy", todir: "${testprojectRoot}/scripts"
}

private void generateArtifacts() {

	callGrails(grailsHome, testprojectRoot, 'dev', 'generate-views') {
		ant.arg value: 'com.testapp.TestRole'
	}

	callGrails(grailsHome, testprojectRoot, 'dev', 'generate-views') {
		ant.arg value: 'com.testapp.TestRequestmap'
	}

	// skip user, needs custom views
}

private void createApp() {

	ant.mkdir dir: projectDir

	deleteDir testprojectRoot
	deleteDir "$dotGrails/projects/$appName"

	callGrails(grailsHome, projectDir, 'dev', 'create-app') {
		ant.arg value: appName
	}
}

private void deleteDir(String path) {
	if (new File(path).exists()) {
		String code = "confirm.delete.$path"
		ant.input message: "$path exists, ok to delete?", addproperty: code, validargs: 'y,n'
		def result = ant.antProject.properties[code]
		if (!'y'.equalsIgnoreCase(result)) {
			ant.echo "\nNot deleting $path"
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

	pluginZip = new File(basedir, "grails-spring-security-core-${pluginVersion}.zip")
	if (!pluginZip.exists()) {
		error "plugin $pluginZip.absolutePath not found"
	}

	grailsHome = config.grailsHome
	if (!new File(grailsHome).exists()) {
		error "Grails home $grailsHome not found"
	}

	projectDir = config.projectDir
	appName = 'spring-security-core-test-' + name
	testprojectRoot = "$projectDir/$appName"
	dotGrails = config.dotGrails
}

private void error(String message) {
	ant.echo "\nERROR: $message"
	exit 1
}

setDefaultTarget 'createTestApp'
