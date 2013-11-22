package pages.role

import geb.Module
import pages.ScaffoldPage

class ListRolePage extends ScaffoldPage {

	static url = 'testRole'

	static at = {
		title ==~ /TestRole List/
	}

	static content = {
		newRoleButton(to: CreateRolePage) { $('a', text: 'New TestRole') }
		roleTable { $('div.content table', 0) }
		roleRow { i -> module RoleRow, roleRows[i] }
		roleRows(required: false) { roleTable.find('tbody').find('tr') }
	}
}

class RoleRow extends Module {
	static content = {
		cell { i -> $('td', i) }
		cellText { i -> cell(i).text() }
		cellHrefText{ i -> cell(i).find('a').text() }
		authority { cellText(0) }
		showLink(to: ShowRolePage) { cell(0).find('a') }
	}
}
