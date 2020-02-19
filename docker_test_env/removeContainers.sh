#!/bin/bash
docker stop dhcpattacker
docker rm dhcpattacker
docker stop dhcpserver
docker rm dhcpserver
docker image rm dhcpattacker
docker network prune -f
