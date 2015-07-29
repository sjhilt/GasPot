# GasPot
GasPot is a honeypot that has been designed to simulate a Veeder Root Gaurdian AST. These Tank Gauges are common in the oil and gas industry for Gas Station tanks to help with Inventory of fuels. GasPot was designed to randomize as much as possible so no two instances look exactly the same. 

## Install
		
	git clone https://github.com/sjhilt/GasPot.git
	

## Configure
GasPot will run as downloaded above with no modifications. However to make sure that GasPot looks like no other GasPot system on the internet to collect the best information there are a few lines of code that should be altered. 

1) Change the station names to match gas stations in the region of deployment of GasPot.
2) Change the product names to match the type of product that would be utlized in the region of deployment. 

## Run GasPot
		
	pythong GasPot.py
	
## Review Logs
All connections will be logged locally to the all_attempts.log file created in the directory that GasPot is ran from. 
	
