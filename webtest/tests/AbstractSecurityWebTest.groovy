import functionaltestplugin.FunctionalTestCase

import com.gargoylesoftware.htmlunit.HttpMethod
import com.gargoylesoftware.htmlunit.WebRequestSettings

import org.springframework.security.authentication.encoding.MessageDigestPasswordEncoder
import org.springframework.util.ReflectionUtils

import java.util.regex.Pattern

import javax.xml.parsers.DocumentBuilderFactory
import javax.xml.xpath.XPathFactory

abstract class AbstractSecurityWebTest extends FunctionalTestCase {

	protected String sessionId

	@Override
	protected void tearDown() {
		super.tearDown()
		logout()
	}

	protected void verifyListSize(int size) {
		int actual = evaluateXpath("count(//div//table//tbody/tr)") as Integer
		assertEquals "$size row(s) of data expected", size, actual
	}

	protected void verifyXPath(String expression, String expected, boolean regex) {
		String result = evaluateXpath(expression)
		if (regex) {
			assertTrue Pattern.compile(expected, Pattern.DOTALL).matcher(result).find()
		}
		else {
			assertEquals expected, result
		}
	}

	protected evaluateXpath(String expression) {
		def documentElement = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(new ByteArrayInputStream(convertResponseToXml().bytes)).documentElement
		XPathFactory.newInstance().newXPath().evaluate(expression, documentElement)
	}

	protected String convertResponseToXml() {
		StringBuilder fixed = new StringBuilder()
		response.contentAsString.eachLine { String line ->
			line = line.replaceAll('&hellip;', '').trim()
			if (!line.startsWith('<link ') && !line.startsWith('<meta ')) {
				fixed << line << '\n'
			}
		}
		fixed.toString().replaceAll('<!doctype ', '<!DOCTYPE ')
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

	protected void login(String username, String password) {
		// login as user1
		get '/login/auth'
		assertContentContains 'Please Login'

		form {
			j_username = username
			j_password = password
			_spring_security_remember_me = true
			clickButton 'Login'
		}
	}

	protected void logout() {
		post '/logout'
	}

	protected MessageDigestPasswordEncoder createSha256Encoder() {
		def passwordEncoder = new MessageDigestPasswordEncoder('SHA-256')
		passwordEncoder.iterations = 10000
		passwordEncoder
	}
}
