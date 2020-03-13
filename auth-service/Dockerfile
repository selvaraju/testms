FROM openjdk
MAINTAINER Piotr Minkowski <piotr.minkowski@gmail.com>
ADD target/auth-service.jar auth-service.jar
ENTRYPOINT ["java", "-jar", "/auth-service.jar"]
EXPOSE 2222