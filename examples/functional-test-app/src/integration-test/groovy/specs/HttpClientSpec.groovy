package specs


import io.micronaut.http.client.BlockingHttpClient
import io.micronaut.http.client.HttpClient
import spock.lang.Shared
import spock.lang.Specification

abstract class HttpClientSpec extends Specification {

    @Shared HttpClient _httpClient
    @Shared BlockingHttpClient _client

    HttpClient getHttpClient() {
        if(!_httpClient) {
            _httpClient = createHttpClient()
        }
        _httpClient
    }

    BlockingHttpClient getClient() {
        if(!_client) {
            _client = getHttpClient().toBlocking()
        }
        _client
    }

    HttpClient createHttpClient() {
        String baseUrl = "http://localhost:$serverPort"
        HttpClient.create(baseUrl.toURL())
    }

    def cleanupSpec() {
        resetHttpClient()
    }

    void resetHttpClient() {
        _httpClient?.close()
        _httpClient = null
        _client = null
    }
}
