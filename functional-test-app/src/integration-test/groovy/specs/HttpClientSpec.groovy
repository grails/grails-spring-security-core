package specs

import grails.testing.spock.OnceBefore
import io.micronaut.http.client.HttpClient
import spock.lang.AutoCleanup
import spock.lang.Shared
import spock.lang.Specification

class HttpClientSpec extends Specification {

    @Shared
    @AutoCleanup
    HttpClient client

    @Shared
    String baseUrl

    @OnceBefore
    void init() {
        this.baseUrl = "http://localhost:$serverPort"
        this.client  = HttpClient.create(new URL(baseUrl))
    }
}
