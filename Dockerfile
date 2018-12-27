FROM openjdk:8
COPY . /usr/src/myapp
COPY lib/* /usr/lib/
WORKDIR /usr/src/myapp
RUN mkdir out -p
RUN javac -cp lib/*:out src/Main.java -d out
CMD ["java", "-Djava.library.path=lib","-cp", "lib/*:out", "Main"]
