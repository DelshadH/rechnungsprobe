FROM maven@sha256:b6ecb971326f147d214081527518bd32bceb55dba3bd5460d9a1d9f4b04464fd AS build
WORKDIR /adapter
COPY pom.xml ./
COPY src/ ./src/
RUN mvn --batch-mode --no-transfer-progress package

FROM eclipse-temurin@sha256:e7ed585b34913e0a780e0282330183a0ea14ad6b929362d02aea1156b43262bf
COPY --from=build /adapter/target/adapter.jar /adapter.jar
ENTRYPOINT ["java", "-jar", "/adapter.jar"]
