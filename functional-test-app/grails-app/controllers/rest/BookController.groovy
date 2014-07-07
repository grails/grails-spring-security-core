package rest

import grails.plugin.springsecurity.annotation.Secured
import grails.rest.RestfulController

@Secured(["ROLE_BOOKS"])
class BookController extends RestfulController{
	static responseFormats = ['json', 'xml']
    static namespace = 'v1'

    public BookController(){
        super(Book)
    }
}
