package grails.plugin.springsecurity

import groovy.json.JsonSlurper
import org.gradle.api.DefaultTask
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.Optional
import org.gradle.api.tasks.OutputFile
import org.gradle.api.tasks.TaskAction

import java.util.regex.Pattern

abstract class CreateReleaseDropDownTask extends DefaultTask {


    private static final Pattern VERSION_PATTERN = Pattern.compile("^[0-9]\\.[0-9]+\\.[0-9]+(-|\\.)?((RC|M)[0-9])?")

    @Input
    abstract Property<String> getGithubSlug()

    @Input
    abstract Property<String> getCurrentVersion()

    @Optional
    @Input
    abstract ListProperty<String> getVersions()

    @Optional
    @OutputFile
    File guide

    @OutputFile
    File index

    @TaskAction
    def createReleaseDropdown() {
        final List<SoftwareVersion> softwareVersions = getSoftwareVersions()
        final String versionHtml = "<span id=\"revnumber\">version ${currentVersion.get()}</span>"
        final String selectHtml = createVersionSelectDropDownHtml(softwareVersions)
        final String versionWithSelectHtml = "<span id=\"revnumber\">version:&nbsp;<span style='display:inline-block;'>${selectHtml}</span></span>"
        if (guide) {
            guide.text = guide.text.replace(versionHtml, versionWithSelectHtml)
        }
        index.text = index.text.replace(versionHtml, versionWithSelectHtml)

    }

    private List<SoftwareVersion> getSoftwareVersions() {
        List<SoftwareVersion> softwareVersions = []
        if (versions.get().isEmpty()) {
            def tags = new JsonSlurper()
                    .parse(new URL("https://api.github.com/repos/${this.githubSlug.get()}/tags"))
            if (tags instanceof List) {
                tags.stream()
                        .<String> map(tagInfo -> { return (String) tagInfo['name'] })
                        .filter(version -> version.startsWith("v"))
                        .map(version -> version.replace("v", ""))
                        .filter(VERSION_PATTERN.asPredicate())
                        .map(version -> SoftwareVersion.build(version))
                        .forEach(softwareVersions::add)
            }
        } else {
            versions.get().stream()
                    .map(version -> SoftwareVersion.build(version))
                    .forEach(softwareVersions::add)
        }

        softwareVersions = softwareVersions
                .sort()
                .unique()
                .reverse()

        softwareVersions
    }

    private String createVersionSelectDropDownHtml(List<SoftwareVersion> softwareVersions) {
        String selectHtml = "<select onChange='window.document.location.href=this.options[this.selectedIndex].value;'>"
        String snapshotHref = "https://grails.github.io/grails-spring-security-core/snapshot/index.html"
        if (currentVersion.get().endsWith("-SNAPSHOT")) {
            selectHtml += "<option selected='selected' value='${snapshotHref}'>SNAPSHOT</option>"
        } else {
            selectHtml += "<option value='${snapshotHref}'>SNAPSHOT</option>"
            selectHtml += "<option selected='selected' value=\"https://grails.github.io/grails-spring-security-core/${currentVersion.get()}/index.html\">${currentVersion.get()}</option>"
        }
        softwareVersions.forEach(softwareVersion -> {
            String versionName = softwareVersion.versionText
            String href = "https://grails.github.io/grails-spring-security-core/${versionName}/index.html"
            if (currentVersion.get() == versionName) {
                selectHtml += "<option selected='selected' value='${href}'>${versionName}</option>"
            } else {
                selectHtml += "<option value='${href}'>${versionName}</option>"
            }
        })
        selectHtml += '</select>'
        selectHtml
    }

}
