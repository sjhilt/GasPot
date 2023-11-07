# GasPot

<p align="center">
<img src="https://github.com/RoseSecurity/GasPot/assets/72598486/bcecc38d-1258-4681-a94c-810e9715c328" width=50% height=50%>
</p>

GasPot is a honeypot that has been designed to simulate a Veeder Root Gaurdian AST. These Tank Gauges are common in the oil and gas industry for Gas Station tanks to help with Inventory of fuels. GasPot was designed to randomize as much as possible so no two instances look identical. 

## Install

```
git clone https://github.com/sjhilt/GasPot.git
```

## Configure

GasPot will run as downloaded above with no modifications. Configuration is based on a config.ini file. To make sure that GasPot looks like no other GasPot system on the internet and to collect the best information you can change the products and stations in the configuration file. 


1) Change the station names to match gas stations in the region of deployment of GasPot.

2) Change the product names to match the type of product that would be utlized in the region of deployment.

## Run GasPot

```
python3 GasPot.py
```

## Review Logs

All connections will be logged locally to the all_attempts.log file created in the directory that GasPot is ran from.

## Docker Install

Download the Docker image from the registry.

```
docker pull rosesecurity/gaspot:v0.1.0
```

Create the container.

```
docker run --name gaspot -p 10001:10001 rosesecurity/gaspot:v0.1.0
```

## Write up

http://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/the-gaspot-experiment


## Stargazers over time

[![Stargazers over time](https://starchart.cc/sjhilt/GasPot.svg)](https://starchart.cc/sjhilt/GasPot)


