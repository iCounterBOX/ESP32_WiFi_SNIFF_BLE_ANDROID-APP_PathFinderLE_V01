# ESP32_WiFi_SNIFF_BLE_ANDROID-APP_PathFinderLE_V01
esp32 as wifi Sniffer connected via BLE to Android-App

Target is to create an APP ( Android ) to show my Location on a MAP ( openStreepMaps ? ).
Arround ME on this Map i want  see in RealTime the amount of MobileDevices .

To detect and count those Mobile Devices we will use the ESP32 WEMOS Dev Kit.

Basic setup:

![image](https://user-images.githubusercontent.com/37293282/79842593-5535d080-83b9-11ea-8da9-753dad8b9c50.png)

# ESP32 - Sniffing and first BLE DataTransfer:

Developmentplatform for the esp32 we take VS2017 and vMicro. I recomment this combination as it provoides us some good advantage ( multi-monitoring / good android-Lib-handling etc..)

take care on some specific settings:

![image](https://user-images.githubusercontent.com/37293282/79843948-46501d80-83bb-11ea-95ec-00de08015793.png)

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


 
