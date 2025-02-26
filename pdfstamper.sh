#!/bin/bash

if [ ! -d ./target ]
then
    echo "TSA Client application not compiled. Please, execute 'mvn clean package'"
    exit 1
fi

mvn -q exec:java -D exec.args="$1 $2 $3"