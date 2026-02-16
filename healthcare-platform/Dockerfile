# Stage 1: Build the application
# Using Maven 3.9.6 with Eclipse Temurin 17 for better stability on Render
FROM maven:3.9.6-eclipse-temurin-17 AS build
WORKDIR /app

# Copy only the pom.xml first to leverage Docker's layer caching for dependencies
COPY pom.xml .
RUN mvn dependency:go-offline -B

# Copy the source code and build the fat JAR
COPY src ./src
RUN mvn clean package -DskipTests

# Stage 2: Runtime environment
# Use a slim runtime image to keep the final deployment size small
FROM eclipse-temurin:17-jre-alpine
WORKDIR /app

# Copy the JAR file from the build stage
# The wildcard *.jar ensures it picks up your 'healthcare-platform-0.0.1-SNAPSHOT.jar'
COPY --from=build /app/target/*.jar app.jar

# Expose the default Spring Boot port
EXPOSE 8080

# Run the application
# Note: Ensure your environment variables are set in the Render Dashboard
ENTRYPOINT ["java", "-jar", "app.jar"]
