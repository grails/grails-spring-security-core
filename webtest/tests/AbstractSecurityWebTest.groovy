import functionaltestplugin.FunctionalTestCase

import java.util.regex.Pattern

import com.gargoylesoftware.htmlunit.HttpMethod
import com.gargoylesoftware.htmlunit.WebRequestSettings

import org.springframework.util.ReflectionUtils

abstract class AbstractSecurityWebTest extends FunctionalTestCase {

	protected static final String ROW_COUNT_XPATH = "count(//div[@class='list']//tbody/tr)"

	protected String sessionId

	@Override
	protected void tearDown() {
		super.tearDown()
		get '/logout'
	}

	protected void verifyListSize(int size) {
		assertContentContainsStrict 'List'
		int actual = page.getByXPath(ROW_COUNT_XPATH)[0]
		assertEquals "$size row(s) of data expected", size, actual
	}

	protected void verifyXPath(String xpath, String expected, boolean regex) {
		def results = page.getByXPath(ROW_COUNT_XPATH)
println "\n\n verifyXPath xpath: $xpath expected $expected : $results ${results*.getClass().name}\n\n"
// verifyXPath xpath: //div[@class='message'] expected .*TestRole.*deleted.* : [0.0] [java.lang.Double]

//		if (regex) {
//			assertTrue Pattern.compile(expected, Pattern.DOTALL).matcher(results[0]).find()
//		}
//		else {
//			assertEquals expected, results[0]
//		}
	}

	protected void clickButton(String idOrText) {
		def button = byId(idOrText)
		if (!button) {
			def form = page.forms[0]
			for (element in form.getElementsByAttribute('input', 'type', 'submit')) {
				if (element.valueAttribute == idOrText) {
					button = element
					break
				}
			}
		}

		if (!button) {
			throw new IllegalArgumentException("No such element for id or button text [$idOrText]")
		}

		println "Clicked [$idOrText] which resolved to a [${button.class}]"
		button.click()
		handleRedirects()
	}

	protected void getWithAuth(String url, String username, String password) {
		println "\n\n${'>'*20} Making request to $url using method get ${'>'*20}"

		def pageField = ReflectionUtils.findField(FunctionalTestCase, '_page')
		pageField.accessible = true

		def reqURL = makeRequestURL(pageField.get(this), url)

		println "Initializing web request settings for $reqURL"
		settings = new WebRequestSettings(reqURL)
		settings.httpMethod = HttpMethod.GET
		settings.additionalHeaders = ['Authorization': 'Basic ' + (username + ':' + password).bytes.encodeBase64()]

		dumpRequestInfo(settings)

		response = client.loadWebResponse(settings)
		pageField.set this, client.loadWebResponseInto(response, mainWindow)

		handleRedirects()
	}

	protected String getSessionValue(String name, String sessionId) {
		def settings = new WebRequestSettings(makeRequestURL(page, '/hack/getSessionValue?name=' + name))
		settings.httpMethod = HttpMethod.GET
		settings.additionalHeaders = ['Cookie': 'JSESSIONID=' + sessionId]
		def response = client.loadWebResponse(settings)
		return stripWS(response.contentAsString)
	}

	protected getInNewPage(String url, String sessionId = null) {
		def settings = new WebRequestSettings(makeRequestURL(page, url))
		settings.httpMethod = HttpMethod.GET
		if (sessionId) {
			settings.additionalHeaders = ['Cookie': 'JSESSIONID=' + sessionId]
		}
		dumpRequestInfo(settings)
		return client.loadWebResponse(settings)
	}

	protected String getContent(String url, boolean newPage = false) {
		def res
		if (newPage) {
			res = getInNewPage(url)
		}
		else {
			get url
			res = response
		}
		stripWS res.contentAsString
	}

	def get(url, Closure paramSetup = null) {
		super.get(url, paramSetup)
		def cookie = response.responseHeaders.find { it.name == 'Set-Cookie' }
		if (!cookie) {
			return
		}
		def parts = cookie.value.split(';Path=/')
		sessionId = parts[0] - 'JSESSIONID='
	}
}
