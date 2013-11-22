package pages.requestmap

import geb.Module
import pages.ScaffoldPage

class ListRequestmapPage extends ScaffoldPage {

	static url = 'testRequestmap'

	static at = {
		title ==~ /TestRequestmap List/
	}

	static content = {
		newRequestmapButton(to: CreateRequestmapPage) { $('a', text: 'New TestRequestmap') }
		requestmapTable { $('div.content table', 0) }
		requestmapRows(required: false) { requestmapTable.find('tbody').find('tr') }
		requestmapRow { i -> module RequestmapRow, requestmapRows[i] }
	}
}

class RequestmapRow extends Module {
	static content = {
		cell { i -> $('td', i) }
		cellText { i -> cell(i).text() }
		cellHrefText{ i -> cell(i).find('a').text() }

		configAttribute { cellText(1) }
		showLink(to: ShowRequestmapPage) { cell(0).find('a') }
	}
}
