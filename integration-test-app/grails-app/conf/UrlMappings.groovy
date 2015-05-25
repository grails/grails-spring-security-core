class UrlMappings {

	static mappings = {
		"/$controller/$action?/$id?(.$format)?" {}

		"/"(view:  '/index')
		"500"(view:'/error')
	}
}
