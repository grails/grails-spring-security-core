package pages.role

import pages.ShowPage

class ShowRolePage extends ShowPage {
	static content = {
		editButton(to: EditRolePage) { $('a', text: 'Edit') }
		deleteButton(to: ListRolePage) { $('input', value: 'Delete') }
		row { String text -> $('li.fieldcontain span.property-label', text: text).parent() }
		value { String text -> row(text).find('span.property-value').text() }
		authority { value('Authority') }
	}
}
