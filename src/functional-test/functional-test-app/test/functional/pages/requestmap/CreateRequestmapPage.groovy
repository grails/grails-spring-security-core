package pages.requestmap

import pages.CreatePage

class CreateRequestmapPage extends CreatePage {
	static content = {
		createButton(to: ShowRequestmapPage) { create() }
	}
}
