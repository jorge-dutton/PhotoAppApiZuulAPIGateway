FROM openjdk:11-jdk-slim
VOLUME /tmp
COPY target/*.jar ZuulApiGateway.jar
ENTRYPOINT ["java","-jar","ZuulApiGateway.jar"]
