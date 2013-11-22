package pages.requestmap

import pages.ShowPage

class ShowRequestmapPage extends ShowPage {
	static content = {
		row { String text -> $('li.fieldcontain span.property-label', text: text).parent() }
		value { String text -> row(text).find('span.property-value').text() }

		editButton(to: EditRequestmapPage) { $('a', text: 'Edit') }
		deleteButton(to: ListRequestmapPage) { $('input', value: 'Delete') }
		configAttribute { value('Config Attribute') }
	}
}
