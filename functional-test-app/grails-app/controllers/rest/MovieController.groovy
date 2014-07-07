package rest

import grails.plugin.springsecurity.annotation.Secured
import grails.rest.RestfulController

@Secured(["ROLE_MOVIES"])
class MovieController extends RestfulController{
	static responseFormats = ['json', 'xml']
	
    public MovieController(){
        super(Movie)
    }
}
