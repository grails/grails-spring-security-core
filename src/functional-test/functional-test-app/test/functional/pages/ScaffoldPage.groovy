package pages

import geb.Page

class ScaffoldPage extends Page {
	static content = {
		heading { $('h1') }
		message { $('div.message').text() }
	}

	long getId() {
		driver.currentUrl.substring(driver.currentUrl.lastIndexOf('/') + 1) as Long
	}
}
