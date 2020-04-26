# **STILL WIP**

## Getting Started

This [Apache Maven Wagon](http://maven.apache.org/wagon) implementation is based on the [Jetty Client](https://www.eclipse.org/jetty/documentation/current/http-client.html).
It supports HTTP/1 protocols such http, https and HTTP/2 as well such H2 or H2C (using ALPN or not)  

## Configuration

The Jetty Wagon implementation must be activated first by being added in the build/extensions section of the pom 
or only the extensions part of the `.mvn/extensions.xml` in your project:
```
  <build>
    .....
    <extensions>
      <extension>
        <groupId>org.eclipse.jetty.maven.wagon</groupId>
        <artifactId>jetty-maven-wagon</artifactId>
        <version>1.0.0-SNAPSHOT</version>
      </extension>
    </extensions>
    .....
  </build>
```

Then you can declare central as using h2 connectivity

```
  <repositories>
    <repository>
      <id>central</id>
      <url>h2://repo.maven.apache.org/maven2/</url>
      <releases>
        <enabled>true</enabled>
      </releases>
      <snapshots>
        <enabled>false</enabled>
      </snapshots>
    </repository>
  </repositories>
  <pluginRepositories>
    <pluginRepository>
      <id>central</id>
      <url>h2://repo.maven.apache.org/maven2/</url>
      <releases>
        <enabled>true</enabled>
      </releases>
      <snapshots>
        <enabled>false</enabled>
      </snapshots>
    </pluginRepository>
  </pluginRepositories>
```

