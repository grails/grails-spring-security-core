class UrlMappings {

	static mappings = {
		"/$controller/$action?/$id?(.$format)?" {}

		"/api/v1/books"(resources: 'book', namespace: 'v1')
		"/api/v1/movies"(resources: 'movie')

		"/openNamespaced"(controller: 'namespaced', namespace: 'open')
		"/secureNamespaced"(controller: 'namespaced', namespace: 'secure')

		"/"(view: '/index')

		"401"(view: '/error401')
		"403"(view: '/error403')
		"403"(view: '/error404')
		"500"(view: '/error')
	}
}
