FROM amazoncorretto:25-alpine AS builder

WORKDIR /app/authco

COPY gradle ./gradle
COPY gradlew .
COPY build.gradle settings.gradle ./
RUN chmod +x gradlew && sed -i 's/\r$//' gradlew
RUN ./gradlew dependencies --no-daemon || true

COPY ./src ./src

RUN ./gradlew clean bootJar -x test --no-daemon

FROM eclipse-temurin:25-jre-alpine

RUN addgroup -S authco && adduser -S -G authco -H -s /sbin/nologin authco

WORKDIR /app

COPY --from=builder --chown=authco:authco /app/authco/build/libs/app.jar .

USER authco

EXPOSE 8087

ENTRYPOINT [ "java", "-jar", "app.jar" ]
