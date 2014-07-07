class UrlMappings {

	static mappings = {
        "/$controller/$action?/$id?(.$format)?"{
            constraints {
                // apply constraints here
            }
        }

		"/api/v1/books"(resources:'book', namespace:'v1')
		"/api/v1/movies"(resources:'movie')
        "/"(view:"/index")
        "500"(view:'/error')
		"401"(view:'/error401')
		"403"(view:'/error403')

	}
}

