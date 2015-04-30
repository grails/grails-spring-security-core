package pages.user

import geb.Module
import pages.ScaffoldPage

class ListUserPage extends ScaffoldPage {

	static url = 'testUser'

	static at = {
		title ==~ /TestUser List/
	}

	static content = {
		newUserButton(to: CreateUserPage) { $('a', text: 'New TestUser') }
		userTable { $('div.list table', 0) }
		userRow { i -> module UserRow, userRows[i] }
		userRows(required: false) { userTable.find('tbody').find('tr') }
	}
}

class UserRow extends Module {
	static content = {
		cell { i -> $('td', i) }
		cellText { i -> cell(i).text() }
		cellHrefText{ i -> cell(i).find('a').text() }
		username { cellText(1) }
		userEnabled { 'True' == cellText(2) }
		showLink(to: ShowUserPage) { cell(0).find('a') }
	}
}
