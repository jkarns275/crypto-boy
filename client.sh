#!/bin/bash
ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1'
java -cp out.jar "edu.oswego.crypto.boy.ClientMainKt$main$1" -xxisvictim

