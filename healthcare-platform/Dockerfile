# Stage 1: Build stage
FROM maven:3.9.6-eclipse-temurin-17 AS build
WORKDIR /app

# 1. Copy ONLY the pom.xml first to take advantage of Docker caching
COPY pom.xml .

# 2. Try to resolve dependencies. We add -B (Batch mode) to reduce logs 
# and -DskipTests to ensure we aren't running code yet.
RUN mvn dependency:go-offline -B

# 3. Now copy the actual source code
COPY src ./src

# 4. Package the application
RUN mvn package -DskipTests

# Stage 2: Runtime stage
FROM eclipse-temurin:17-jre-alpine
WORKDIR /app
COPY --from=build /app/target/*.jar app.jar

EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]