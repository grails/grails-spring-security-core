import grails.web.UrlConverter
import test.HackUrlConverter

beans = {
	"$UrlConverter.BEAN_NAME"(HackUrlConverter)
}
