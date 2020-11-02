# PathFinderLE_V02

>>>>>  Complete Documentation please find here: https://github.com/iCounterBOX/ESP32_WiFi_SNIFF_BLE_ANDROID-APP_PathFinderLE_V01/wiki

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

