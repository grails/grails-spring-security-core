package pages.role

import pages.CreatePage

class CreateRolePage extends CreatePage {
	static content = {
		createButton(to: ShowRolePage) { create() }
	}
}
