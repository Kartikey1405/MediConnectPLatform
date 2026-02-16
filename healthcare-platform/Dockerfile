# Stage 1: Build
FROM maven:3.8.4-openjdk-17 AS build
COPY . /app
WORKDIR /app
RUN mvn clean package -DskipTests

# Stage 2: Run
FROM openjdk:17-jdk-slim
WORKDIR /app

# 1. Copy the jar from the build stage
COPY --from=build /app/target/*.jar app.jar

# 2. IMPORTANT: Copy your .env file so Dotenv can read it
COPY .env .env

EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
