# Образ собирается из готового дистрибутива: сначала `./gradlew installDist` (vulscan-kit берётся из mavenLocal).
FROM eclipse-temurin:21-jre
RUN groupadd --system app && useradd --system --gid app --no-create-home app
WORKDIR /app
COPY build/install/vulscan-xss-module/ /app/
USER app
ENV JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=70 -XX:+ExitOnOutOfMemoryError"
EXPOSE 8081
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=3 \
  CMD ["java", "-cp", "/app/lib/*", "io.vulscan.xss.health.HealthCheckKt"]
ENTRYPOINT ["/app/bin/vulscan-xss-module"]
