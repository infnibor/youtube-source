import com.vanniktech.maven.publish.JavaLibrary
import com.vanniktech.maven.publish.JavadocJar
import org.apache.tools.ant.filters.ReplaceTokens

plugins {
    `java-library`
    alias(libs.plugins.maven.publish.base)
}

base {
    archivesName = "youtube-v2"
}

dependencies {
    api(projects.common)
    compileOnly(libs.lavaplayer.v2)

    implementation(libs.rhino.engine)
    implementation(libs.nanojson)
    compileOnly(libs.slf4j)
    compileOnly(libs.annotations)

    testImplementation(libs.lavaplayer.v2)
}

mavenPublishing {
    coordinates("dev.infnibor.youtube", "v2", version.toString())
    configure(JavaLibrary(JavadocJar.Javadoc()))
}

tasks {
    processResources {
        filter<ReplaceTokens>(
            "tokens" to mapOf(
                "version" to project.version
            )
        )
    }
}
