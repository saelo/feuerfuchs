#!/bin/bash

docker exec -it feuerfuchs bash -c 'DISPLAY=:1 import -window root /tmp/screenshot.png'
docker cp feuerfuchs:/tmp/screenshot.png .
