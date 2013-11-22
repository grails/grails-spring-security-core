package pages.user

import pages.ShowPage

class ShowUserPage extends ShowPage {
	static content = {
		editButton(to: EditUserPage) { $('a', text: 'Edit') }
		deleteButton(to: ListUserPage) { $('input', value: 'Delete') }
		username { $('td#username').text() }
		enabled { $('td#userEnabled').text() == 'True' }
	}
}
