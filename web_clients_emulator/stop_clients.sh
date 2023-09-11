#!/bin/bash
docker stop if1
docker stop if2
docker stop if3
docker stop if4
docker stop if5
docker stop if6
docker stop if7
docker stop if8
docker rm if1
docker rm if2
docker rm if3
docker rm if4
docker rm if5
docker rm if6
docker rm if7
docker rm if8
docker network rm macvlan0

