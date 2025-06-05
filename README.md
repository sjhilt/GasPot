# GasPot

## UPDATED VERSION

This honeypot is an adapted vestion of GasPot developed by sjhilt. Changes include more granular time stamps and fixing the bug where access logs are not written to a file when running the software in docker due to buffers not being written to the log file.

GasPot is a honeypot that has been designed to simulate a Veeder Root Gaurdian AST. These Tank Gauges are common in the oil and gas industry for Gas Station tanks to help with Inventory of fuels. GasPot was designed to randomize as much as possible so no two instances look identical. 

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

It would be reccomended to run GasPot within docker. To do this, you need to run the command below:

`docker-compose up --build -d`

NOTE: Before you do this, you need to run the following commands on your local system to make the required user, group and directory for log persistence.

```
addgroup --gid 10001 --system veeder
adduser --uid 10000 --system --ingroup veeder --home /home/veeder veeder
mkdir -p /data/logs/GasPot/
touch /data/logs/GasPot/all_attempts.log
```

## Write up

Below is the write up of the original GasPot version developed at BlackHat 2015.

http://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/the-gaspot-experiment
