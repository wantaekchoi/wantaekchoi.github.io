plugins { application }

repositories {
    mavenCentral()
    maven { url = uri("https://nexus.1edtech.net/repository/1edtech-public-release/") }
    maven { url = uri("https://repo.danubetech.com/repository/maven-public") }
    maven { url = uri("https://jitpack.io") }                       // com.github.* coordinates
    maven { url = uri("https://repo.osgeo.org/repository/release/") } // GeoTools, via tableschema-java
}

dependencies {
    implementation("org.1edtech:inspector-vc:1.11.0")   // OB30Inspector + Danubetech, transitively
    implementation("org.bouncycastle:bcprov-jdk18on:1.85.2")
}

// tableschema-java pulls GeoTools, which depends on an artifact Oracle never published.
// No geospatial code path is reachable from the inspector, so drop it.
configurations.all { exclude(group = "javax.media", module = "jai_core") }

java { toolchain { languageVersion = JavaLanguageVersion.of(21) } }
application { mainClass = "wk.Signer" }
