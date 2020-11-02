/*
ESP + SNIFFER + BL classic / M5STICK C

OK  - scanner-app wird der string nun angezeigt - service und level werden richtig angezeigt
ACHTUNG...Auf der scanner-app uU mal  REFRESH SERVICES anklicken


Sniffs WiFi Packets in promiscuous mode, Identifies Known Mac addresses and keeps track of how long they have been in proximity.

13.06.20:
Sniffer & PathFinder V2.0
Sniffer zeigt jetzt mit dem M5 Home-Button die eigene BT MAC an..diese wird dann in die Options vom PathFinder eingetragen.
MAC Addr Setzen
SET MAC  - geht noch nicht
https://www.reddit.com/r/esp32/comments/9jmkf9/here_is_how_you_set_a_custom_mac_address_on_esp32/

esp_wifi_set_mode(WIFI_MODE_NULL); // OR WHATEVER mode we need.  In master case Station WIFI_STA or Slave case WIFI_AP
esp_wifi_set_mac(ESP_IF_WIFI_AP, &ESP32mac[0]); // ESP32 code


09.06.20:
DRIVE: https://drive.google.com/drive/folders/1BSWMFluffBK2aWEv52oQ7DsJL95-97wu
DAS hier wird die Double-Node-like version! Sniff läuft hier in ein struct-array (super).
M5 Display geht auf ROT wenn wir wir eine SocialDistancing-Violation haben.
New: wir senden jetzt automatisch zum PathFinder ( warten NICHT den Request ab  )..
D.h wenn die 14 Kanäle durch sind, dann wird zum pLE die Transmission gestartet..pLE macht den RX auf die Daten und zeigt diese korrekt an
G E I L


https://www.hackster.io/p99will/esp32-wifi-mac-scanner-sniffer-promiscuous-4c12f4

ESP32 sniffer...ausführlich m vielen details:
https://github.com/ETS-PoliTO/esp32-sniffer

had huge problem with compiling ( was too big ):
================================================
Tools -> Partition Scheme: change "Default" to "Huge APP(3MB No OTA)"
https://github.com/espressif/arduino-esp32/issues/1075

ESP + SNIFFER + BL classic:
https://circuitdigest.com/microcontroller-projects/using-classic-bluetooth-in-esp32-and-toogle-an-led

M5 StickC:
==========
https://github.com/electricidea/M5StickC-TB_Display
https://www.hackster.io/hague/m5stickc-textbuffer-scrolling-display-fb6428
https://github.com/electricidea/M5StickC-TB_Display

8,0|30E37A46C76,-92|200000,-87|239A843C9B,-91|22AF357BFFC,-92|3293664A19D,-94|D2652DAB42B1,-91|D28B17D8943D,-84|2EA514BC2F,-86|1854CF6CDE15,-95|BE1BE6EC2A98,-92|861AA928614,-82|1AAAA2D1D89B,-95|86CE74FC8885,-94|42188E81ADFB,-90|4E51B587DF26,-93|B827EB9A27D6,-87|EA3550D167A0,-91|F05C7739A8E5,-92|AE5886C475D3,-89|E231C7CAADE6,-91|829DF3E0D276,-91|A6893AB1D94C,-92|723D21CEAAD1,-93|6E2FC39FF71E,-95



ESP32 ( das modul mit den pins...nicht der M5 !! ) kann nicht beschrieben werden ..Plash BUTTON drücken :




*/

#include <M5StickC.h>
#include "esp_wifi.h"
#include "nvs_flash.h"
#include <WiFi.h>

#include "BluetoothSerial.h" //Header File for Serial Bluetooth, will be added by default into Arduino
#include "esp_bt_device.h"  // für die adresse des BT devices...die MAC addr

#include "tb_display.h"

//M5STICK C

// Display brightness level
// possible values: 7 - 15
uint8_t screen_brightness = 12;

// scren Rotation values:
// 1 = Button right
// 2 = Button above
// 3 = Button left
// 4 = Button below
int screen_orientation = 3;

// BLE SECTOR / See the following for generating UUIDs:
#if !defined(CONFIG_BT_ENABLED) || !defined(CONFIG_BLUEDROID_ENABLED)
#error Bluetooth is not enabled! Please run `make menuconfig` to and enable it
#endif

BluetoothSerial SerialBT;

int incoming;
int LED_BUILTIN = 2;

int oledRowCount = 0;

String _str4BLtransfer = "";
bool weHaveASocialDistanceViolation = false;

// Handle received and sent messages
String _messageFromPathFinder = "";
String _currentPhoneTime = "";
// Timer: auxiliar variables
unsigned long previousMillis = 0;    // Stores last time temperature was published
const long interval = 700;         // interval at which to publish scan results

bool mobilePhoneIsReady4Transmission = false;

// SNIFFER - SECTOR ******************************

/* TAG of ESP32 for I/O operation */
static const char *TAG = "ETS";


// A Struct Array to keep the sniffed MAC devices

typedef struct {
	char deviceMacAddr[14];						// peerMac		
	signed int rssi = 0;						// RSSI			
} deviceRecordType;

#define _MACdeviceDataMAXelements  200
deviceRecordType  _MACdeviceData[_MACdeviceDataMAXelements];		// instead of EDB we try hier a STRUCT ARRAY
int _MACdeviceDataIndex = 0;	    // Index of this Struct Array

char _btMacAddr[] = "000000000000";  // Die BT MAC die der PathFinder für die Kommunikation benötigt

typedef struct {
	int16_t fctl; //frame control
	int16_t duration; //duration id
	uint8_t da[6]; //receiver address
	uint8_t sa[6]; //sender address
	uint8_t bssid[6]; //filtering address
	int16_t seqctl; //sequence control
	unsigned char payload[]; //network data
} __attribute__((packed)) wifi_mgmt_hdr;

#define maxCh 13 //max Channel -> US = 11, EU = 13, Japan = 14

int curChannel = 1;


static void getMAC(char* addr, uint8_t* data, uint16_t offset)
{
	sprintf(addr, "%02x%02x%02x%02x%02x%02x", data[offset + 0], data[offset + 1], data[offset + 2], data[offset + 3], data[offset + 4], data[offset + 5]);
}


void sniffer(void* buf, wifi_promiscuous_pkt_type_t type) { //This is where packets end up after they get sniffed

	int pkt_len, fc;
	time_t ts;

	wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
	wifi_mgmt_hdr *mgmt = (wifi_mgmt_hdr *)pkt->payload;
	fc = ntohs(mgmt->fctl);

	if ((fc & 0xFF00) == 0x4000) { //only look for probe request packets
		time(&ts);
		pkt_len = pkt->rx_ctrl.sig_len;

		String packet;
		
		char deviceMacAddr[] = "000000000000";
		int fctl = ntohs(mgmt->fctl);

		for (int i = 8; i <= 8 + 6 + 1; i++) { // This reads the first couple of bytes of the packet. This is where you can read the whole packet replaceing the "8+6+1" with "p->rx_ctrl.sig_len"
			packet += String(pkt->payload[i], HEX);			
		}
		packet.toUpperCase();		


		// MAC as char buffer
		for (int i = 4, ii = 0; i <= 15; i++, ii++) { // This removes the 'nibble' bits from the stat and end of the data we want. So we only get the mac address.			
			deviceMacAddr[ii] = packet[i];
		}
		Serial.print("> "); Serial.print(deviceMacAddr); Serial.print(","); Serial.println(pkt->rx_ctrl.rssi);

		// Igno-Check ..step OUT it MAC is from my own NB e.g....Muss alles im pLE in die DB
		// Serial.print("Ignore: "); Serial.println(deviceMacAddr);
		

		if (strcmp(deviceMacAddr, "50E085863526") == 0) 
			return;  // ACER NITRO 5
		if (strcmp(deviceMacAddr, "9CB6D017E3A9") == 0)
			return;  // MSI
			

		// NEW - STRUCT DATA 		

		int idx = findMACdeviceInDeviceArray(deviceMacAddr);	// FIRST we check if this MAC was Stored before within this SCAN-CYCLE ( e.g 20 SEC for 14 Cgannel ) -- Gives the Index or -1

		if (idx == -1) {		// Hurray - a NEW Wifi X-Mas-Tree
			//int nElements = sizeof _MACdeviceData / sizeof _MACdeviceData[0];		// ?? gab den vordefinierten wert zurück der Stuktur ?? Nicht den gerade gespeicherten Element-Count?
			if (_MACdeviceDataIndex < _MACdeviceDataMAXelements) {				// In _MACdeviceDataMAXelements MUSS Immer der aktuelle Index stehen		
				strncpy(_MACdeviceData[_MACdeviceDataIndex].deviceMacAddr, deviceMacAddr, sizeof _MACdeviceData[_MACdeviceDataIndex].deviceMacAddr - 1);
				_MACdeviceData[_MACdeviceDataIndex].rssi = pkt->rx_ctrl.rssi;
				/*
				Serial.print(" INSERTed - NEW Device  in Struct-array: "); 	Serial.print(_MACdeviceData[_MACdeviceDataIndex].deviceMacAddr);
				Serial.print(" rssi: "); Serial.println(_MACdeviceData[_MACdeviceDataIndex].rssi);
				*/
				_MACdeviceDataIndex += 1;
			}
			else
			{
				Serial.print(" ALERT!! - _MACdeviceData / Limit Reached!!:  "); Serial.println(_MACdeviceDataMAXelements);
				return;
			}
		}
		else {														//  ***  UPDATE EXISTING WiFi DEVICE
			/*
			Serial.print("Element Found at Position: "); Serial.println( idx + 1);
			Serial.print("  UPDATE - rssi) : "); Serial.println(deviceMacAddr);
			Serial.print("vor/_MACdeviceData[idx].rssi: "); Serial.println(_MACdeviceData[idx].rssi);
			-30 dBm ist größer/stärker als -90 dBm  also näher dran - wir nehmen vom scan nur die stärksten ( näher )
			*/

			if (_MACdeviceData[idx].rssi < pkt->rx_ctrl.rssi)
				_MACdeviceData[idx].rssi = pkt->rx_ctrl.rssi;

			//Serial.print(" New rssi: "); Serial.println(_MACdeviceData[idx].rssi);  
		}

	}
}

// STRUCT ARRAY FUNCTIONS:  SEARCH , EDIT
/*
Check if the NEW detected device is almost stored in the Array

Parameter:
peermac - the detected peerMAC of a device
nrElements = (sizeof _MACdeviceData / sizeof _MACdeviceData[0])		-- // https://stackoverflow.com/questions/1898657/result-of-sizeof-on-array-of-structs-in-c
return: gives the index of the peerMAC found in array

*/

int findMACdeviceInDeviceArray(char *peerMAC) {
	int nElements = _MACdeviceDataIndex;
	for (int i = 0; i <= nElements; i++)
	{
		if (strcmp(_MACdeviceData[i].deviceMacAddr, peerMAC) == 0) {					// the function returns 0 when the strings are equal			
			//Serial.print("findMACdeviceInDeviceArray() FOUND it : ");	Serial.println(MACdeviceData[i].deviceMacAddr);
			return i;
		}
	}
	return -1;
}


esp_err_t event_handler(void *ctx, system_event_t *event)
{
	return ESP_OK;
}

//===== SETUP =====//

//Print Device Addr of BT   https://www.dfrobot.com/blog-870.html
/*
Leider funktioniert der plan den Namen mit der MAC zusammen zu bastel nicht...BT muss erst initialisiert sein,
dann kann ich erst diese MAC abrufen!?

*/
void printDeviceAddress(char * mac) {
	const uint8_t* point = esp_bt_dev_get_address();

	sprintf(mac, "%02X%02X%02X%02X%02X%02X", (int)point[0], (int)point[1], (int)point[2], (int)point[3], (int)point[4], (int)point[5]);

	for (int i = 0; i < 6; i++) {
		char str[3];
		sprintf(str, "%02X", (int)point[i]);
		Serial.print(str);
		if (i < 5) {
			Serial.print(":");
		}		
	}	
}

//uint8_t ESP32mac[] = { 0xB4, 0xE6, 0x2D, 0xB2, 0x1B, 0x36 }; //{0x36, 0x33, 0x33, 0x33, 0x33, 0x33};

void setup() {
	

	/* start Serial */
	Serial.begin(115200);
	
	// M5 STICK start
	M5.begin();
	pinMode(M5_BUTTON_HOME, INPUT);
	// set screen brightness
	M5.Axp.ScreenBreath(screen_brightness);
	// init the text buffer display and print welcome text on the display

	// print a welcome message over serial porta
	Serial.println("===================");
	Serial.println(" PathFinderLE");
	Serial.println("   M5StickC");
	Serial.println(" 05.06.2020 v1.0");
	Serial.println("===================");

	// init the text buffer display and print welcome text on the display
	tb_display_init(screen_orientation);
	tb_display_print_String("        PathFinderLE\n\n   V.2.0\n\n");

	/* SNIFFER - SECTOR / setup wifi */
	nvs_flash_init();
	tcpip_adapter_init();
	ESP_ERROR_CHECK(esp_event_loop_init(event_handler, NULL));
	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
	ESP_ERROR_CHECK(esp_wifi_init(&cfg));
	Serial.print("curChannel: "); Serial.println(curChannel);
	esp_wifi_set_storage(WIFI_STORAGE_RAM);
	esp_wifi_set_mode(WIFI_MODE_NULL);
	esp_wifi_start();
	esp_wifi_set_promiscuous(true);
	esp_wifi_set_promiscuous_rx_cb(&sniffer);
	esp_wifi_set_channel(curChannel, WIFI_SECOND_CHAN_NONE);
	Serial.println("SNIFF-SECTOR / Starting!");

	/*
	BL classic SECTOR
	*/

	SerialBT.begin("ESP32test"); //Bluetooth device name
	Serial.println("The device started, now you can pair it with bluetooth!");
	pinMode(LED_BUILTIN, OUTPUT);//Specify that LED pin is output,,the blue LED on ESP
	Serial.println("Bluetooth Device is Ready to Pair");

	//ESP32 Modul-Addresse:  https://randomnerdtutorials.com/get-change-esp32-esp8266-mac-address-arduino/		
	Serial.println();
	Serial.print("ESP Board MAC Address:  ");	Serial.println(WiFi.macAddress());

	//BT Device MAC ADDR : https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/bluetooth/esp_bt_device.html

	
	Serial.print("ESP BT MAC Address:  ");  printDeviceAddress(_btMacAddr);
	Serial.println();

	Serial.print("Device Name for PathFinder: ESP_"); Serial.println(_btMacAddr);	
}


long randNumber;

void generateTheTransferString() { // This updates the time the device has been online for
	randNumber = random(99);
	String logString = "";
	_str4BLtransfer = String(randNumber, DEC) + ",0";   // wir setzen den TX string wieder zurück...im loop wird der neu gefüllt	
	for (int i = 0; i < _MACdeviceDataIndex; i++) {
		String mac = _MACdeviceData[i].deviceMacAddr;
		_str4BLtransfer += "|" + mac + "," + _MACdeviceData[i].rssi;
		if (abs(_MACdeviceData[i].rssi) < 40) {		// größer 1 sonst erfassen wir die random zahl
			weHaveASocialDistanceViolation = true;
			Serial.println("weHaveASocialDistanceViolation = true");
		}
	}
	//Serial.println("TransferString is Ready: ");
	Serial.println(_str4BLtransfer);
}

void showDataOnM5Display() {
	// M5 STICK Message / Length (with one extra character for the null terminator)
	if (digitalRead(M5_BUTTON_HOME) == LOW) {
		Serial.print("BT MAC: "); Serial.println(_btMacAddr);
		
		M5.Lcd.fillScreen(WHITE);
		M5.Lcd.setCursor(10, 10);
		M5.Lcd.setTextColor(RED);		
		M5.Lcd.setTextSize(1);  // 1,2,3
		M5.Lcd.println(_currentPhoneTime);
		M5.Lcd.println("ESP BT MAC:");
		M5.Lcd.println(_btMacAddr);
	}
	else {
		M5.Lcd.setTextSize(1);
		if (weHaveASocialDistanceViolation == true) {
			M5.Lcd.setTextColor(TFT_RED, TFT_BLACK);
		}
		else {
			M5.Lcd.setTextColor(TFT_WHITE, TFT_BLACK);
		}
		String strM5 = _str4BLtransfer + "\n";
		strM5.replace("|", "\n");
		int str_len = strM5.length() + 1;
		//Serial.print("len: "); Serial.println(str_len);
		char c[800];
		strM5.toCharArray(c, str_len);
		tb_display_print_String(c, 70);
	}	
}




//===== LOOP =====//
void loop() {

	// Read received messages (LED control command)
	if (SerialBT.available()) {
		char incomingChar = SerialBT.read();
		if (incomingChar != '\n') {
			_messageFromPathFinder += String(incomingChar);
		}
		else {
			_messageFromPathFinder = "";
		}
		//Serial.write(incomingChar); // DAS schreibt das gerade empfangene CHAR auf den lokalen Monitor
	}
	// Check received message and control output accordingly
	if (_messageFromPathFinder.length() >= 16) {
		_currentPhoneTime = _messageFromPathFinder;
		_messageFromPathFinder = "";
		Serial.print("PathFinder Time: "); Serial.println(_currentPhoneTime);
		mobilePhoneIsReady4Transmission = true;
	}

	unsigned long currentMillis = millis();
	// Change the Channel each X sec
	if (currentMillis - previousMillis >= interval) {
		previousMillis = currentMillis;
		Serial.println("CH:" + String(curChannel));
		if (curChannel > maxCh) {
			curChannel = 1;		// RESET the CHANNEL
			generateTheTransferString();

			// ready to send
			/*
			if ( mobilePhoneIsReady4Transmission)  {
				SerialBT.println(_str4BLtransfer);
				mobilePhoneIsReady4Transmission = false;
			}
			*/

			SerialBT.println(_str4BLtransfer); // TX

			showDataOnM5Display();
			// RESET  + ERASE the buffers - Clear the _MACdeviceData-struct  + RESET the Display color
			memset(_MACdeviceData, 0, sizeof(_MACdeviceData));  //clear_MACdeviceDataStuct();
			_MACdeviceDataIndex = 0;
			_str4BLtransfer = "";
			M5.Lcd.setTextColor(TFT_WHITE, TFT_BLACK);
			weHaveASocialDistanceViolation = false;
		}
		esp_wifi_set_channel(curChannel, WIFI_SECOND_CHAN_NONE);
		curChannel++;
	}

	// BLE stuff
	// ?? bet  https://randomnerdtutorials.com/esp32-bluetooth-classic-arduino-ide/




	//M5.update();

}

