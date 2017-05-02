// tag::packageImport[]
package com.mycompany.myapp

// end::packageImport[]
// tag::import[]
import grails.plugin.springsecurity.annotation.Secured

// end::import[]

// tag::securedAnnotation[]
@Secured('ROLE_ADMIN')
// end::securedAnnotation[]

// tag::class[]
class SecureController {
// end::class[]
   // tag::methodAnnotation[]
   @Secured('ROLE_ADMIN')
   // end::methodAnnotation[]
   // tag::index[]
   def index() {
      render 'Secure access only'
   }
   // end::index[]
// tag::classClose[]
}
// end::classClose[]
