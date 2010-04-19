import grails.util.GrailsUtil

import java.lang.reflect.Modifier

import junit.framework.TestCase
import junit.framework.TestSuite

import org.codehaus.groovy.grails.commons.ApplicationHolder
import org.codehaus.groovy.grails.support.PersistenceContextInterceptor
import org.codehaus.groovy.grails.test.GrailsTestTargetPattern
import org.codehaus.groovy.grails.test.GrailsTestType
import org.codehaus.groovy.grails.test.GrailsTestTypeResult
import org.codehaus.groovy.grails.test.event.GrailsTestEventPublisher
import org.codehaus.groovy.grails.test.event.GrailsTestEventConsoleReporter
import org.codehaus.groovy.grails.test.junit3.JUnit3GrailsTestType
import org.codehaus.groovy.grails.test.junit3.JUnit3GrailsTestTypeMode
import org.codehaus.groovy.grails.test.junit3.JUnit3GrailsTestTypeResult
import org.codehaus.groovy.grails.test.junit3.JUnit3GrailsTestTypeRunner
import org.codehaus.groovy.grails.test.report.junit.JUnitReportProcessor
import org.codehaus.groovy.grails.test.report.junit.JUnitReportsFactory
import org.codehaus.groovy.grails.test.support.GrailsTestTypeSupport

import org.springframework.util.Assert

includeTargets << grailsScript('_GrailsBootstrap')
includeTargets << grailsScript('_GrailsRun')
includeTargets << grailsScript('_GrailsSettings')
includeTargets << grailsScript('_GrailsClean')

currentTestPhaseName = 'functional'
currentTestTypeName = 'functional'
testNames = ['**.*']
testTargetPatterns = null // created in allTests()
reportFormats = [ 'xml', 'plain' ]
testReportsDir = grailsSettings.testReportsDir
testSourceDir = grailsSettings.testSourceDir
testOptions = [:]

testEventPublisher = new GrailsTestEventPublisher(event)

// Add a listener to write test status updates to the console
eventListener.addGrailsBuildListener(new GrailsTestEventConsoleReporter(System.out))

// Add a listener to generate our JUnit reports.
eventListener.addGrailsBuildListener(new JUnitReportProcessor())

// The 'styledir' argument to the 'junitreport' ant task (null == default provided by Ant)
junitReportStyleDir = null

ant.path(id: 'grails.test.classpath', testClasspath)

createTestReports = true
testsFailed = false

target(allTests: 'Runs functional tests') {
	depends(clean, compile, packagePlugins)

	packageFiles(basedir)

	ant.mkdir(dir: testReportsDir)
	ant.mkdir(dir: "${testReportsDir}/html")
	ant.mkdir(dir: "${testReportsDir}/plain")

	testTargetPatterns = testNames.collect { new GrailsTestTargetPattern(it) } as GrailsTestTargetPattern[]

	try {

		def suitesToRun = args.split('\n') as List
		def type = new TestHelper(basedir, suitesToRun)

		println()

		packageApp()
		testOptions.https ? runAppHttps() : runApp()
		prevAppCtx = binding.hasProperty('appCtx') ? appCtx : null
		appCtx = ApplicationHolder.application.mainContext
		initPersistenceContext()

		def sourceDir = new File(testSourceDir, 'functional')
		def classesDir = new File(grailsSettings.testClassesDir, 'functional')
		compileTests(type, sourceDir, classesDir)
		runTests(type, classesDir)

		destroyPersistenceContext()
		appCtx?.close()
		appCtx = prevAppCtx
		stopServer()
	}
	finally {
		String msg = testsFailed ? '\nTests FAILED' : '\nTests PASSED'
		if (createTestReports) {
			event('TestProduceReports', [])
			msg += " - view reports in ${testReportsDir}"
		}
		event('StatusFinal', [msg])
		event('TestPhasesEnd', [])
	}

	testsFailed ? 1 : 0
}

compileTests = { GrailsTestType type, File source, File dest ->
	event('TestCompileStart', [type])

	ant.mkdir(dir: dest.path)
	try {
		def classpathId = 'grails.test.classpath'
		ant.groovyc(destdir: dest, encoding:'UTF-8', classpathref: classpathId, verbose: grailsSettings.verboseCompile, listfiles: grailsSettings.verboseCompile) {
			javac(classpathref: classpathId, debug: 'yes')
			src(path: source)
		}
	}
	catch (Exception e) {
		event('StatusFinal', ["Compilation error compiling [$type.name] tests: ${e.message}"])
		exit 1
	}

	event('TestCompileEnd', [type])
}

runTests = { GrailsTestType type, File compiledClassesDir ->
	def testCount = type.prepare(testTargetPatterns, compiledClassesDir, binding)

	if (testCount) {
		try {
			event('TestSuiteStart', [type.name])
			println ''
			println '-------------------------------------------------------'
			println "Running ${testCount} $type.name test${testCount > 1 ? 's' : ''}..."

			def start = new Date()
			def result = type.run(testEventPublisher)
			def end = new Date()

			event('StatusUpdate', ["Tests Completed in ${end.time - start.time}ms"])

			if (result.failCount > 0) testsFailed = true

			println '-------------------------------------------------------'
			println "Tests passed: ${result.passCount}"
			println "Tests failed: ${result.failCount}"
			println '-------------------------------------------------------'
			event('TestSuiteEnd', [type.name])
		}
		catch (Exception e) {
			event('StatusFinal', ["Error running $type.name tests: ${e.toString()}"])
			GrailsUtil.deepSanitize(e)
			e.printStackTrace()
			testsFailed = true
		}
		finally {
			type.cleanup()
		}
	}
}

initPersistenceContext = { appCtx.getBeansOfType(PersistenceContextInterceptor).values()*.init() }
destroyPersistenceContext = { appCtx.getBeansOfType(PersistenceContextInterceptor).values()*.destroy() }

setDefaultTarget 'allTests'

class TestHelper extends GrailsTestTypeSupport {

	private _suitesToRun
	private _basedir
	private TestSuite _wholeTestSuite
	private _mode = new JUnit3GrailsTestTypeMode(
		autowire: true,
		wrapInTransaction: false,
		wrapInRequestEnvironment: false)

	TestHelper(basedir, suitesToRun) {
		super('functional', 'functional')
		_basedir = basedir
		_suitesToRun = suitesToRun
	}

	@Override
	protected List<String> getTestSuffixes() { ['Suite'] }

	@Override
	protected int doPrepare() {
		createWholeTestSuite()
		_wholeTestSuite.testCount()
	}

	private void createWholeTestSuite() {
		_wholeTestSuite = new TestSuite('Grails Test Suite')

		def resolveResources = buildBinding['resolveResources']
		def resources = resolveResources("file:${_basedir}/test/functional/**/*Suite.groovy".toString())
		def allFiles = resources*.file.findAll { _suitesToRun.contains(it.name - '.groovy') }
		for (File sourceFile : allFiles) {

			Class<?> clazz = sourceFileToClass(sourceFile)
			if (TestCase.isAssignableFrom(clazz) && !Modifier.isAbstract(clazz.getModifiers())) {
				TestSuite suite = clazz.suite()
				suite.testCount().times { _wholeTestSuite.addTest(suite.testAt(it)) }
			}
		}
	}

	private getApplicationContext() {
		def buildBinding = getBuildBinding()
		Assert.state(buildBinding.variables.containsKey('appCtx'),
				'ApplicationContext requested, but is not present in the build binding')
		buildBinding.getProperty('appCtx')
	}

	@Override
	protected GrailsTestTypeResult doRun(GrailsTestEventPublisher eventPublisher) {
		JUnit3GrailsTestTypeRunner runner = new JUnit3GrailsTestTypeRunner(
				JUnitReportsFactory.createFromBuildBinding(getBuildBinding()),
				eventPublisher, createSystemOutAndErrSwapper())
		new JUnit3GrailsTestTypeResult(runner.runTests(_wholeTestSuite))
	}
}
