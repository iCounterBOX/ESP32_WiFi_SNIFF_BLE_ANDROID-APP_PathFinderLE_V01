# PathFinderLE_V02

![image](https://user-images.githubusercontent.com/37293282/97838122-d9a9ca00-1cdf-11eb-957b-64715ebd4b73.png)

At its core, Pathfinder is a tool for **dynamic counting** and storage  of mobil devices motion-profiles
Technically, the process is based on so-called WiFi-Beacons, Bluetooth beacons and BLE-C19-Exposure-Beacons.
After a brief introduction to this technology, we will look at some example use cases.



![image](https://user-images.githubusercontent.com/37293282/97839501-98ff8000-1ce2-11eb-8c8a-67c08e523eff.png)

We are surrounded by many devices that send out these beacons. Some send BlueTooth  .. some WiFi.
PathFinder scans these beacons and saves them locally for further statistical analysis.
PathFinder AND M5 ( an ESP32 Module ) form a very powerful PAIR - If M5 is NOT available, then our APP processes ONLY BT or BLE beacons.
Via RSSI signal we derive a distance value from this in a mathematically prepared manner. Similar to the procedure we also know from the official Corona warning app (CWA) ). On this basis, PathFinder can also recognize an SDV (Social distancing Violation) and, if necessary, trigger further alarms.


![image](https://user-images.githubusercontent.com/37293282/97839603-cb10e200-1ce2-11eb-8d45-d27e9df6e372.png)


We summarize again briefly
- PathFinder is essentially a **mobile device beacon signal scanner**
- This procedure provides data. These are recorded and saved in a local database


![image](https://user-images.githubusercontent.com/37293282/97839698-fabfea00-1ce2-11eb-89ae-3116bdc17a65.png)


PathFinder already provides some very meaningful statistics ... like visitor statistics or people counting
- Counting based on BT ( classic )
- Counting based on BLE ( BT low Energy )
- Counting on C19 Exposure-Notification-Beacons


![image](https://user-images.githubusercontent.com/37293282/97839900-5db18100-1ce3-11eb-8bde-2da511924493.png)

From our point of view the "**Market Density Indicator**" is a very strong UC 

The scenario:
In times of Corona we want to avoid very full supermarkets. And there are also long queues at the cash registers and no parking spaces in front of the market.

In the Market  PathFinder works as a data provider. The data is sent to the backend in the cloud.. The supermarket customer ONLY needs the PathFinder APP to receive the Market Density-Information.



# what do we need to run PathFinder?

The PathFinder Android APP is self-sufficient!
Does not need WiFi (Home LAN or something else..) - does not burden the data volume (from your provider)!

The ESP32 Espresif MCU is required for PathFinder to scan  WiFi beacons - but not a MUST!

**Pathfinder APP / WITHOUT M5 (ESP-32):**

WiFi beacon scan is NOT done. This means that ONLY statistical evaluations are available for BT / BLE and EXPOSURE (C19).

**Pathfinder APP / WITH M5 (ESP-32):**

In this combination, ESP (e.g. M5) scans the WiFi. ESP periodically transmits the collected WiFi beacons via BT to the PathFinder APP.
In the PathFinder APP, these scans are then stored in a SQlite DB for further processing.



# Thanks for the sources of knowledge that I found on the web

ESP32-Wifi-Beacon-Scanner:

This sniffer example here base on some existing code i found on other GitHub-Repos here - thx-credidits to those!  some of them exist only in cpp. so they need some adaption to get compiled as INO. 

ETS-PoliTO / esp32-sniffer  https://github.com/ETS-PoliTO/esp32-sniffer/blob/master/main/main.c  
ESP32 WiFi MAC Scanner/Sniffer (promiscuous): https://www.hackster.io/p99will/esp32-wifi-mac-scanner-sniffer-promiscuous-4c12f4
ESP32 – WiFi sniffer: https://blog.podkalicki.com/esp32-wifi-sniffer/

Another code source is from my study of beacon-scan via the NODE MCU ESP8266..documented here on my Github.

Quite new for me is this BLE-Topoic as the NodeMCU does not have the BLE on board. BLE is a very huge lib. we need to take care to have the right settings..otherwise it cannot be compiled ( err: code is too big ..)

![image](https://user-images.githubusercontent.com/37293282/79845188-f8d4b000-83bc-11ea-8fa2-819493c353c6.png)

State: 21.04.20

Example code ( https://github.com/iCounterBOX/ESP32_WiFi_SNIFF_BLE_ANDROID-APP_PathFinderLE_V01/tree/master/EXAMPLES/ESP32_bleWrite2Mobile )  is sniffing MAC and just send some CHAR letters vis BLE to my mobile phone.
I test  this with android-App: BLE SCANNER.
Is working fine and is schowing that it is basically possible to combine this promiscuous-Mode in combination with the BLE from the ESP32


 
