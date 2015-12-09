
integrationTest {
	def file = new File('testconfig')
	String testconfig = file.exists() ? file.text.trim().toLowerCase() : 'annotation'
	def tests
	switch (testconfig) {
		case 'annotation': tests = ['AnnotationSecurity', 'InheritanceSecurity', 'NamespaceSecurity', 'Role', 'User']; break
		case 'basic':      tests = ['BasicAuthSecurity', 'Role', 'User']; break
		case 'bcrypt':     tests = ['BCrypt']; break
		case 'misc':       tests = ['Disable', 'Misc']; break
		case 'requestmap': tests = ['Requestmap', 'RequestmapSecurity', 'Role', 'User']; break
		case 'static':     tests = ['Role', 'StaticSecurity', 'User']; break
		default: throw new GradleException('File testconfig must exist and contain one of annotation, basic, bcrypt, misc, requestmap, or static')
	}

	tests.each { include "**/${it}Spec.class" }

	doFirst {
		logger.quiet "\n - Running test(s) $tests for configuration '$testconfig' with Grails $grailsVersion"
	}

	beforeTest { descriptor -> logger.quiet " -- $descriptor" }
}

// deletes everything from the build directory except for test reports
task cleanBuild {
	File build = file('build')
	if (!build.exists()) return

	build.eachFile {
		if (it.file) {
			it.delete()
		}
		else if (it.name != 'reports' && !it.name.startsWith('geb-reports') && !it.name.startsWith('test-results')) {
			it.deleteDir()
		}
	}
}
