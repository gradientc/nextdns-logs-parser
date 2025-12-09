# **NextDNS Logs Parser**

Here's a script I put together to handle NextDNS log exports.

If you've ever tried to open a 2GB+ CSV file in Excel, you know it usually ends in tears (and sometimes a crashed PC). 
NextDNS is brilliant, but their analytics dashboard caps out at 3 months. So here's a log parser specifically designed for NextDNS CSV exports. 
It can analyse even your biggest logs spanning a year or more, without choking your PC.

It's not an official NextDNS project ; merely a tool to help parse those massive CSV dumps they let you download.

## **What it actually does**

* **It's fast-ish:** Uses polars instead of pandas, so it streams the data rather than eating all your memory. It chews through gigabytes of logs fairly quickly.  
* **Proper splitting:** NextDNS sometimes lists multiple blocklists in one cell (e.g., "oisd, 1hosts"). This script actually splits them up so your stats aren't rubbish.  
* **Threat sorting:** separates the "dodgy stuff" (malware, phishing, C2) from the "annoying stuff" (ads, trackers), so you can see if your network is possibly compromised or just blocking some ads.  
* **HTML dashboard:** Spits out a single .html file with charts and a world map. It uses CDNs for the visuals, so you'll need an internet connection to view the report.

## **How to run it**

1. **Get your logs:** Go to your NextDNS settings page and download the CSV.  
2. **Install dependencies:** You'll need Python installed. Then install the package:  
   `pip install .`

3. Run the thing:  
   Drop your CSV in the same folder and run:  
   `python nextdns-logs-parser.py`

   It'll find the CSV automatically. If you want to be specific or change the output format:  
   `python nextdns-logs-parser.py \--input my-logs.csv \--format txt`

## **Disclaimer (The boring bit)**

This comes with absolutely **no warranty**. It works on my machine, and it parses the logs correctly for my setup, but I haven't tested it on every edge case.

I'm not affiliated with NextDNS. Use this entirely at your own risk. If it breaks, you get to keep both pieces.

## **Licence**

AGPLv3. Fork it. Fix it. Run it. Share it.