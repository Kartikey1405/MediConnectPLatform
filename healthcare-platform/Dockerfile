# Stage 1: Build stage
FROM maven:3.9.6-eclipse-temurin-17 AS build
WORKDIR /app

# 1. Copy the pom.xml first
COPY pom.xml .

# 2. Pre-download dependencies. We add the -P (Profile) or just clean
# to ensure the Spring Milestone repo is used immediately.
RUN mvn dependency:go-offline -B

# 3. Copy source and build
COPY src ./src
RUN mvn package -DskipTests

# Stage 2: Runtime stage
FROM eclipse-temurin:17-jre-alpine
WORKDIR /app
COPY --from=build /app/target/*.jar app.jar

EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]