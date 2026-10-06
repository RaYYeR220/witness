#!/bin/sh
# Registers three sample InfrastructureElements so Trust Manager has something to score.
until curl -sf http://orion-ld:1026/ngsi-ld/ex/v1/version >/dev/null; do sleep 2; done
curl -s -X POST http://orion-ld:1026/ngsi-ld/v1/entityOperations/upsert/ \
  -H "Content-Type: application/json" \
  -H 'Link: <https://uri.etsi.org/ngsi-ld/v1/ngsi-ld-core-context.jsonld>; rel="http://www.w3.org/ns/json-ld#context"; type="application/ld+json"' \
  -d '[
    {"id":"urn:ngsi-ld:InfrastructureElement:MyDomain:fa163e5e25ef","type":"InfrastructureElement",
     "cpuCores":4,"currentCpuUsage":15,"ramCapacity":15615,"availableRam":5462,"currentRamUsage":10153,
     "internalIpAddress":"10.0.0.186","macAddress":"fa:16:3e:5e:25:ef"},
    {"id":"urn:ngsi-ld:InfrastructureElement:MyDomain:fa163e32c6ee","type":"InfrastructureElement",
     "cpuCores":4,"currentCpuUsage":3,"ramCapacity":15615,"availableRam":13307,"currentRamUsage":2308,
     "internalIpAddress":"10.0.0.238","macAddress":"fa:16:3e:32:c6:ee"},
    {"id":"urn:ngsi-ld:InfrastructureElement:MyDomain:fa163ed55867","type":"InfrastructureElement",
     "cpuCores":2,"currentCpuUsage":100,"ramCapacity":7753,"availableRam":948,"currentRamUsage":6805,
     "internalIpAddress":"10.0.0.16","macAddress":"fa:16:3e:d5:58:67"}
  ]'
echo "orion seeded"
