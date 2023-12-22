import org.openqa.selenium.chrome.ChromeDriver
import org.openqa.selenium.chrome.ChromeOptions
import org.openqa.selenium.firefox.FirefoxDriver
import org.openqa.selenium.firefox.FirefoxOptions
import org.openqa.selenium.firefox.GeckoDriverService

private static FirefoxDriver createFirefoxDriver(FirefoxOptions options = new FirefoxOptions()) {
    def osName = System.getProperty('os.name').toLowerCase()
    def profileRoot = osName.contains('linux') && new File('/snap/firefox').exists() ? createProfileRootInUserHome() : null
    profileRoot ? new FirefoxDriver(createGeckoDriverService(profileRoot), options) : new FirefoxDriver(options)
}

private static String createProfileRootInUserHome() {
    def profileRoot = [System.getProperty('user.home'), 'snap/firefox/common/.firefox-profile-root'] as File
    if ( ! profileRoot.exists()) {
        if ( ! profileRoot.mkdirs()) {
            return null
        }
    }
    profileRoot.absolutePath
}

private static GeckoDriverService createGeckoDriverService(String tmpProfileDir) {
    new GeckoDriverService.Builder() {
        @Override
        protected List<String> createArgs() {
            def args = new ArrayList(super.createArgs())
            def idx = args.indexOf('--profile-root')
            if (idx > -1) {
                args.remove(idx + 1)
                args.remove(idx)
            }
            args.add '--profile-root'
            args.add tmpProfileDir
            args
        }
    }.build()
}

environments {

    // run via “./gradlew -Dgeb.env=chrome iT”
    chrome {
        driver = { new ChromeDriver() }
    }

    // run via “./gradlew -Dgeb.env=chromeHeadless iT”
    chromeHeadless {
        driver = {
            ChromeOptions o = new ChromeOptions()
            o.addArguments '--headless=new'
            o.addArguments '--remote-allow-origins=*'
            new ChromeDriver(o)
        }
    }

    // run via “./gradlew -Dgeb.env=firefox iT”
    firefox {
        driver = { createFirefoxDriver() }
    }

    firefoxHeadless {
        driver = {
            FirefoxOptions o = new FirefoxOptions()
            o.addArguments '-headless'
            createFirefoxDriver o
        }
    }
}

waiting {
    timeout = 10
    retryInterval = 0.5
}