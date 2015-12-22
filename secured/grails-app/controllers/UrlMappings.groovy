class UrlMappings {

	static mappings = {
		"/$controller/$action?/$id?(.$format)?"{}

		"/"(view:   '/index')
		"404"(view: '/notFound')
		"500"(view: '/error')
	}
}
