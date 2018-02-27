#ifndef APScan_h
#define APScan_h

#define maxAPScanResults  30

#include <ESP8266WiFi.h>
#include "Mac.hpp"
#include "MacList.hpp"
#include "Settings.hpp"
#include <ESP8266WebServer.h>

extern String           data_getVendor ( uint8_t first, uint8_t second,
	uint8_t third );
extern ESP8266WebServer server;
extern void             sendBuffer();
extern void             sendToBuffer ( String str );
extern void             sendHeader ( int code, String type, size_t _size );
extern const bool       debug;

extern Settings         settings;

class                   APScan {
	public:
		APScan();
		
		void    sort();
		void    select ( int num );
		void    sendResults();
		
  	String  getResultsJSON();
		String  getAPName ( int num );
		String  getAPEncryption ( int num );		
		String  getAPMac ( int num );
  	String  sanitizeJson ( String input );
  
  	bool    isSelected ( int num );
		bool    isHidden ( int num );
  	bool    start();
  
		int     getAPRSSI ( int num );
		int     getAPChannel ( int num );
		int     getFirstTarget();
		int     results = 0;
		int     selectedSum;
  
		MacList aps;
  
	private:
		int     channels[maxAPScanResults];
		int     rssi[maxAPScanResults];
		int     encryption[maxAPScanResults];
		char    names[maxAPScanResults][33];
  
		bool    hidden[maxAPScanResults];
		bool    selected[maxAPScanResults];
		
		String  getEncryption ( int code );
};
#endif
