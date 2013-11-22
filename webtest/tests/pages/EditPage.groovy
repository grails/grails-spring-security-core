package pages

import geb.Page

class EditPage extends ScaffoldPage {
	static at = {
		heading.text() ==~ /Edit.+/
	}
}
