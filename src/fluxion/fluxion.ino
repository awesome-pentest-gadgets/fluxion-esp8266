/*
 ***********************************************************************
           https://github.com/FluxionNetwork/fluxion-esp8266
 *                                                                     *
                           (c) 2018 Cyberfee
 *                                                                     *
         fluxion-esp8266 is based on spacehuhn/esp8266_deauther
                            (c) Stefan Kremser
 **********************************************************************
*/

// *********************************************************************
// ** LIBARIES
// *********************************************************************
#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <FS.h>
#include <ESP8266HTTPUpdateServer.h>
#include <WiFiClient.h>
#include <DNSServer.h>
#include <ESP8266mDNS.h>

// *********************************************************************
// ** SETTINGS
// *********************************************************************

/*
  Enable using GPIO0 (Flash button on NodeMCUs)
  as a deauth attack toggle (CAN LEAD TO LED BLINKING BUG!)
*/
#define GPIO0_DEAUTH_BUTTON

/* comment out or change if you need GPIO 4 for other purposes */
#define resetPin  4

/*
  for the Pocket ESP8266 which has a LED on GPIO 16 to indicate if it's running
*/
//#define USE_LED16

/*Define baudrate*/
#define BAUD 115200

// Max channel
#define MAX_CHAN 13

/* Dns redirection */
const byte DNS_PORT = 53;
DNSServer dnsServer;

// network parameters
IPAddress apIP(192, 168, 4, 1);
IPAddress netMsk(255, 255, 255, 0);

// external libaries
extern "C" {
#include "user_interface.h"
}

const byte              web_port = 80;
ESP8266WebServer        server ( web_port );
ESP8266HTTPUpdateServer httpUpdater;

#include <EEPROM.h>
#include "includes/data.hpp"
#include "includes/NameList.hpp"
#include "includes/APScan.hpp"
#include "includes/ClientScan.hpp"
#include "includes/Attack.hpp"
#include "includes/Settings.hpp"
#include "includes/SSIDList.hpp"

// *********************************
// DEBUG
// *********************************
const bool    debug = true;

// Run-Time Variables //
String        wifiMode = "";
String        attackMode_deauth = "";
String        attackMode_beacon = "";
String        scanMode = "SCAN";

// Deauth detector
bool          detecting = false;
unsigned long dC = 0;
unsigned long prevTime = 0;
unsigned long curTime = 0;
int           curChannel = settings.detectorChannel;

NameList      nameList;

APScan        apScan;
ClientScan    clientScan;
Attack        attack;
Settings      settings;
SSIDList      ssidList;

// *********************************************************************
// ** Custom functions

// *********************************************************************
void sniffer ( uint8_t* buf, uint16_t len )
{
  clientScan.packetSniffer ( buf, len );
}

void startWifi()
{
  Serial.println ( "Start fluxion" );
  Serial.println ( "" );
  Serial.println ( "[I] Starting WiFi AP" );
  WiFi.mode ( WIFI_AP_STA );
  wifi_set_promiscuous_rx_cb ( sniffer );
  WiFi.softAP ( ( const char* ) settings.ssid.c_str (),
                ( const char* ) settings.password.c_str (), settings.apChannel,
                settings.ssidHidden ); //for an open network without a password change to:  WiFi.softAP(ssid);

  if ( settings.wifiClient && settings.ssidClient ) {
    Serial.print ( "[I] Connecting to WiFi network '" + settings.ssidClient +
                   "' using the password '" + settings.passwordClient + "' " );

    if ( settings.hostname ) {
      WiFi.hostname ( settings.hostname );
    }

    WiFi.begin ( ( const char* ) settings.ssidClient.c_str (),
                 ( const char* ) settings.passwordClient.c_str () );
    int conAtt = 0;

    while ( WiFi.status () != WL_CONNECTED ) {
      delay ( 500 );
      Serial.print ( "." );
      conAtt++;

      if ( conAtt > 30 ) {
        Serial.println ( "" );
        Serial.println ( "[E] Failed to connect to '" + settings.ssidClient +
                         "', skipping connection\n" );
        goto startWifi;
      }
    }

    Serial.println ( "[+] Connected!" );
    Serial.print ( "IP address: " );
    Serial.println ( WiFi.localIP () );
    Serial.print ( "Netmask: " );
    Serial.println ( WiFi.subnetMask () );
    Serial.print ( "Gateway: " );
    Serial.println ( WiFi.gatewayIP () );
    Serial.println ( "" );
  }

startWifi:
  Serial.println ( "SSID          : '" + settings.ssid + "'" );
  Serial.println ( "Password      : '" + settings.password + "'" );

  if ( settings.newUser == 1 )
  {
    Serial.println ( "[+] Redirecting to setup page" );
  }

  Serial.println ( "-----------------------------------------------" );

  if ( settings.password.length () < 8 )
  {
    Serial.println ( "[W] Password must have at least 8 characters!" );
  }

  if ( settings.ssid.length () < 1 || settings.ssid.length () > 32 )
  {
    Serial.println ( "[W] SSID length must be between 1 and 32 characters!" );
  }

  wifiMode = "ON";
}

// *********************************************************************
// **In case we want to stop the AP

// *********************************************************************
void stopWifi()
{
  Serial.println ( "[-] Stopping WiFi AP" );
  WiFi.disconnect ();
  wifi_set_opmode ( STATION_MODE );
  wifiMode = "OFF";
}

// *********************************************************************
// ** Load the site

// *********************************************************************
void httpDefault ()
{
  server.sendHeader("Location", settings.hostname, true);
  server.send(302, "text/plain", "");
  server.client().stop();
}

void loadSetupHTML()
{
  if (server.hostHeader() != String(settings.hostname)) {
    return httpDefault();
  }
  
  server.sendHeader ( "Cache-Control", "no-cache, no-store, must-revalidate" );
  server.sendHeader ( "Pragma", "no-cache" );
  server.sendHeader ( "Expires", "0" );
  sendFile ( 200, "text/html", data_setup_HTML, sizeof ( data_setup_HTML ),
             true );
}

void loadIndexHTML()
{
  sendFile ( 200, "text/html", data_index_HTML, sizeof ( data_index_HTML ),
             false );
}

void loadUsersHTML()
{
  sendFile ( 200, "text/html", data_users_HTML, sizeof ( data_users_HTML ),
             false );
}

void loadAttackHTML()
{
  attack.ssidChange = true;
  sendFile ( 200, "text/html", data_attack_HTML, sizeof ( data_attack_HTML ),
             false );
}

void loadDetectorHTML()
{
  sendFile ( 200, "text/html", data_detector_HTML, sizeof ( data_detector_HTML ),
             false );
}

void loadControlHTML()
{
  sendFile ( 200, "text/html", data_control_HTML, sizeof ( data_control_HTML ),
             false );
}

void loadSettingsHTML()
{
  sendFile ( 200, "text/html", data_settings_HTML, sizeof ( data_settings_HTML ),
             false );
}

void load404()
{
  sendFile ( 404, "text/html", data_404_HTML, sizeof ( data_404_HTML ), false );
}

void loadInfoHTML()
{
  sendFile ( 200, "text/html", data_info_HTML, sizeof ( data_info_HTML ), false );
}

void loadScanJS()
{
  sendFile ( 200, "text/javascript", data_scan_JS, sizeof ( data_scan_JS ),
             false );
}

void loadUsersJS()
{
  sendFile ( 200, "text/javascript", data_users_JS, sizeof ( data_users_JS ),
             false );
}

void loadAttackJS()
{
  attack.ssidChange = true;
  sendFile ( 200, "text/javascript", data_attack_JS, sizeof ( data_attack_JS ),
             false );
}

void loadDetectorJS()
{
  sendFile ( 200, "text/javascript", data_detector_JS,
             sizeof ( data_detector_JS ),
             false );
}

void loadControlJS()
{
  sendFile ( 200, "text/javascript", data_control_JS, sizeof ( data_control_JS ),
             false );
}

void loadSettingsJS()
{
  sendFile ( 200, "text/javascript", data_settings_JS,
             sizeof ( data_settings_JS ),
             false );
}

void loadInfoJS()
{
  sendFile ( 200, "text/javascript", data_info_JS, sizeof ( data_info_JS ),
             false );
}

void loadFunctionsJS()
{
  sendFile ( 200, "text/javascript", data_functions_JS,
             sizeof ( data_functions_JS ), false );
}

void loadStyle()
{
  sendFile ( 200, "text/css;charset=UTF-8", data_main_CSS,
             sizeof ( data_main_CSS ), false );
}

void loadDarkMode()
{
  if ( settings.darkMode ) {
    sendFile ( 200, "text/css;charset=UTF-8", data_dark_CSS,
               sizeof ( data_dark_CSS ), true );
  }

  else {
    server.send ( 200, "text/css", "/* Dark mode disabled */" );
  }
}

void loadDarkModeForce()
{
  sendFile ( 200, "text/css;charset=UTF-8", data_dark_CSS,
             sizeof ( data_dark_CSS ), true );
}

void loadRedirectHTML()
{
  server.send ( 302, "text/html",
                "<meta content='0; url=http://192.168.4.1'http-equiv='refresh'>" );
}

void startWiFi ( bool start )
{
  if ( start )
  {
    startWifi ();
  }

  else
  {
    stopWifi ();
  }

}

// *********************************************************************
// ** AP SCAN

// *********************************************************************
void startAPScan()
{
  scanMode = "[I] Scanning";

  if ( apScan.start () ) {
    server.send ( 200, "text/json", "true" );
    attack.stopAll ();
    scanMode = "SCAN";
  }
}

// *********************************************************************
// ** Syntify results
// *********************************************************************
void sendAPResults()
{
  apScan.sendResults ();
}

// *********************************************************************
// ** Web UI
// *********************************************************************
void selectAP()
{
  if ( server.hasArg ( "num" ) ) {
    apScan.select ( server.arg ( "num" ).toInt () );
    server.send ( 200, "text/json", "true" );
    attack.stopAll ();
  }
}

// *********************************************************************
// ** scan for wifi clients
// *********************************************************************
void startClientScan()
{
  if ( server.hasArg ( "time" ) && apScan.getFirstTarget () > -1 &&
       !clientScan.sniffing ) {
    server.send ( 200, "text/json", "true" );
    clientScan.start ( server.arg ( "time" ).toInt () );
    attack.stopAll ();
  }

  else
  {
    server.send ( 200, "text/json", "ERROR: No selected Wi-Fi networks!" );
  }
}

// *********************************************************************
// ** print results
// *********************************************************************
void sendClientResults()
{
  clientScan.send ();
}

// *********************************************************************
// ** get scan time
// *********************************************************************
void sendClientScanTime()
{
  server.send ( 200, "text/json", ( String ) settings.clientScanTime );
}

// *********************************************************************
// ** select any clients
// *********************************************************************
void selectClient()
{
  if ( server.hasArg ( "num" ) ) {
    clientScan.select ( server.arg ( "num" ).toInt () );
    attack.stop ( 0 );
    server.send ( 200, "text/json", "true" );
  }
}

// *********************************************************************
// ** Add clients to target list
// *********************************************************************
void addClientFromList()
{
  if ( server.hasArg ( "num" ) ) {
    int _num = server.arg ( "num" ).toInt ();
    clientScan.add ( nameList.getMac ( _num ) );
    server.send ( 200, "text/json", "true" );
  }

  else
  {
    server.send ( 200, "text/json", "false" );
  }
}

// *********************************************************************
// ** Set custom names
// *********************************************************************
void setClientName()
{
  if ( server.hasArg ( "id" ) && server.hasArg ( "name" ) ) {
    if ( server.arg ( "name" ).length () > 0 ) {
      nameList.add ( clientScan.getClientMac ( server.arg ( "id" ).toInt () ),
                     server.arg ( "name" ) );
      server.send ( 200, "text/json", "true" );
    }

    else
    {
      server.send ( 200, "text/json", "false" );
    }
  }
}

// *********************************************************************
// ** Delete any unwanted names
// *********************************************************************
void deleteName()
{
  if ( server.hasArg ( "num" ) ) {
    int _num = server.arg ( "num" ).toInt ();
    nameList.remove ( _num );
    server.send ( 200, "text/json", "true" );
  }

  else
  {
    server.send ( 200, "text/json", "false" );
  }
}

// *********************************************************************
// ** Clear list
// *********************************************************************
void clearNameList()
{
  nameList.clear ();
  server.send ( 200, "text/json", "true" );
}

// *********************************************************************
// ** edit client names
// *********************************************************************
void editClientName()
{
  if ( server.hasArg ( "id" ) && server.hasArg ( "name" ) ) {
    nameList.edit ( server.arg ( "id" ).toInt (), server.arg ( "name" ) );
    server.send ( 200, "text/json", "true" );
  }

  else
  {
    server.send ( 200, "text/json", "false" );
  }
}

// *********************************************************************
// ** custom clients
// *********************************************************************
void addClient()
{
  if ( server.hasArg ( "mac" ) && server.hasArg ( "name" ) ) {
    String  macStr = server.arg ( "mac" );
    macStr.replace ( ":", "" );
    Serial.println ( "add " + macStr + " - " + server.arg ( "name" ) );

    if ( macStr.length () < 12 || macStr.length () > 12 )
    {
      server.send ( 200, "text/json", "false" );
    }

    else {
      Mac _newClient;

      for ( int i = 0; i < 6; i++ ) {
        const char*  val = macStr.substring ( i * 2, i * 2 + 2 ).c_str ();
        uint8_t     valByte = strtoul ( val, NULL, 16 );
        Serial.print ( valByte, HEX );
        Serial.print ( ":" );
        _newClient.setAt ( valByte, i );
      }

      Serial.println ();
      nameList.add ( _newClient, server.arg ( "name" ) );
      server.send ( 200, "text/json", "true" );
    }
  }
}

// *********************************************************************
// ** Syntify attack results

// *********************************************************************
void sendAttackInfo()
{
  attack.sendResults ();
}

// *********************************************************************
// ** Start attacks

// *********************************************************************
void startAttack()
{
  if ( server.hasArg ( "num" ) ) {
    int _attackNum = server.arg ( "num" ).toInt ();

    if ( apScan.getFirstTarget () > -1 || _attackNum == 1 || _attackNum == 2 ) {
      attack.start ( server.arg ( "num" ).toInt () );
      server.send ( 200, "text/json", "true" );
    }

    else
    {
      server.send ( 200, "text/json", "false" );
    }
  }
}

// *********************************************************************
// ** Add custom essid

// *********************************************************************
void addSSID()
{
  if ( server.hasArg ( "ssid" ) && server.hasArg ( "num" ) &&
       server.hasArg ( "enc" ) ) {
    int num = server.arg ( "num" ).toInt ();

    if ( num > 0 ) {
      ssidList.addClone ( server.arg ( "ssid" ), num,
                          server.arg ( "enc" ) == "true" );
    }

    else {
      ssidList.add ( server.arg ( "ssid" ),
                     server.arg ( "enc" ) == "true" || server.arg ( "enc" ) == "1" );
    }

    attack.ssidChange = true;
    server.send ( 200, "text/json", "true" );
  }

  else
  {
    server.send ( 200, "text/json", "false" );
  }
}

// *********************************************************************
// ** Clone selected network

// *********************************************************************
void cloneSelected()
{
  if ( apScan.selectedSum > 0 ) {
    int clonesPerSSID = 48 / apScan.selectedSum;
    ssidList.clear ();

    for ( int i = 0; i < apScan.results; i++ ) {
      if ( apScan.isSelected ( i ) ) {
        ssidList.addClone ( apScan.getAPName ( i ), clonesPerSSID,
                            apScan.getAPEncryption ( i ) != "none" );
      }
    }
  }

  attack.ssidChange = true;
  server.send ( 200, "text/json", "true" );
}

// *********************************************************************
// ** Delete selected ssids

// *********************************************************************
void deleteSSID()
{
  ssidList.remove ( server.arg ( "num" ).toInt () );
  attack.ssidChange = true;
  server.send ( 200, "text/json", "true" );
}

// *********************************************************************
// ** Generate any random essids

// *********************************************************************
void randomSSID()
{
  ssidList._random ();
  attack.ssidChange = true;
  server.send ( 200, "text/json", "true" );
}

// *********************************************************************
// ** Clear ssid attack list

// *********************************************************************
void clearSSID()
{
  ssidList.clear ();
  attack.ssidChange = true;
  server.send ( 200, "text/json", "true" );
}

void resetSSID()
{
  ssidList.load ();
  attack.ssidChange = true;
  server.send ( 200, "text/json", "true" );
}

void reloadSSID()
{
  attack.ssidChange = true;
  server.send ( 200, "text/json", "true" );
}

void saveSSID()
{
  ssidList.save ();
  server.send ( 200, "text/json", "true" );
}

void restartESP()
{
  server.send ( 200, "text/json", "true" );
  ESP.restart ();
}

void enableRandom()
{
  server.send ( 200, "text/json", "true" );
  attack.changeRandom ( server.arg ( "interval" ).toInt () );
}

void startDetector()
{
  Serial.println ( "Starting Deauth Detector..." );
  server.send ( 200, "text/json", "true" );
  wifi_set_opmode ( STATION_MODE );
  wifi_promiscuous_enable ( 0 );
  WiFi.disconnect ();
  wifi_set_promiscuous_rx_cb ( dSniffer );
  wifi_set_channel ( curChannel );
  wifi_promiscuous_enable ( 1 );
  pinMode ( settings.alertPin, OUTPUT );
  detecting = true;
}

void dSniffer ( uint8_t* buf, uint16_t len )
{
  if ( buf[12] == 0xA0 || buf[12] == 0xC0 ) {
    dC++;
  }
}

// *********************************************************************
// ** Get settings on the settings list
// *********************************************************************
void getSettings()
{
  settings.send ();
}

void getSysInfo()
{
  settings.sendSysInfo ();
}

void saveSettings()
{
  server.send ( 200, "text/json", "true" );

  if ( server.hasArg ( "ssid" ) ) {
    settings.ssid = server.arg ( "ssid" );
  }

  if ( server.hasArg ( "ssidHidden" ) ) {
    if ( server.arg ( "ssidHidden" ) == "false" )
    {
      settings.ssidHidden = false;
    }

    else
    {
      settings.ssidHidden = true;
    }
  }

  if ( server.hasArg ( "password" ) )
  {
    settings.password = server.arg ( "password" );
  }

  if ( server.hasArg ( "apChannel" ) ) {
    if ( server.arg ( "apChannel" ).toInt () >= 1 &&
         server.arg ( "apChannel" ).toInt () <= 14 ) {
      settings.apChannel = server.arg ( "apChannel" ).toInt ();
    }
  }

  if ( server.hasArg ( "wifiClient" ) ) {
    if ( server.arg ( "wifiClient" ) == "false" )
    {
      settings.wifiClient = false;
    }

    else
    {
      settings.wifiClient = true;
    }
  }

  if ( server.hasArg ( "ssidClient" ) )
  {
    settings.ssidClient = server.arg ( "ssidClient" );
  }

  if ( server.hasArg ( "passwordClient" ) )
  {
    settings.passwordClient = server.arg ( "passwordClient" );
  }

  if ( server.hasArg ( "hostname" ) )
  {
    settings.hostname = server.arg ( "hostname" );
  }

  if ( server.hasArg ( "macAp" ) ) {
    String  macStr = server.arg ( "macAp" );
    macStr.replace ( ":", "" );
    Mac tempMac;

    if ( macStr.length () == 12 ) {
      for ( int i = 0; i < 6; i++ ) {
        const char*  val = macStr.substring ( i * 2, i * 2 + 2 ).c_str ();
        uint8_t     valByte = strtoul ( val, NULL, 16 );
        tempMac.setAt ( valByte, i );
      }

      if ( tempMac.valid () ) {
        settings.macAP.set ( tempMac );
      }
    }

    else if ( macStr.length () == 0 ) {
      settings.macAP.set ( settings.defaultMacAP );
    }
  }

  if ( server.hasArg ( "randMacAp" ) ) {
    if ( server.arg ( "randMacAp" ) == "false" )
    {
      settings.isMacAPRand = false;
    }

    else
    {
      settings.isMacAPRand = true;
    }
  }

  if ( server.hasArg ( "macAp" ) ) {
    String  macStr = server.arg ( "macAp" );
    macStr.replace ( ":", "" );
    Mac tempMac;

    if ( macStr.length () == 12 ) {
      for ( int i = 0; i < 6; i++ ) {
        const char*  val = macStr.substring ( i * 2, i * 2 + 2 ).c_str ();
        uint8_t     valByte = strtoul ( val, NULL, 16 );
        tempMac.setAt ( valByte, i );
      }

      if ( tempMac.valid () ) {
        settings.macAP.set ( tempMac );
      }
    }

    else if ( macStr.length () == 0 ) {
      settings.macAP.set ( settings.defaultMacAP );
    }
  }

  if ( server.hasArg ( "randMacAp" ) ) {
    if ( server.arg ( "randMacAp" ) == "false" )
    {
      settings.isMacAPRand = false;
    }

    else
    {
      settings.isMacAPRand = true;
    }
  }

  if ( server.hasArg ( "scanTime" ) )
  {
    settings.clientScanTime = server.arg ( "scanTime" ).toInt ();
  }

  if ( server.hasArg ( "timeout" ) )
  {
    settings.attackTimeout = server.arg ( "timeout" ).toInt ();
  }

  if ( server.hasArg ( "deauthReason" ) )
  {
    settings.deauthReason = server.arg ( "deauthReason" ).toInt ();
  }

  if ( server.hasArg ( "packetRate" ) )
  {
    settings.attackPacketRate = server.arg ( "packetRate" ).toInt ();
  }

  if ( server.hasArg ( "apScanHidden" ) ) {
    if ( server.arg ( "apScanHidden" ) == "false" )
    {
      settings.apScanHidden = false;
    }

    else
    {
      settings.apScanHidden = true;
    }
  }

  if ( server.hasArg ( "beaconInterval" ) ) {
    if ( server.arg ( "beaconInterval" ) == "false" )
    {
      settings.beaconInterval = false;
    }

    else
    {
      settings.beaconInterval = true;
    }
  }

  if ( server.hasArg ( "useLed" ) ) {
    if ( server.arg ( "useLed" ) == "false" )
    {
      settings.useLed = false;
    }

    else
    {
      settings.useLed = true;
    }

    attack.refreshLed ();
  }

  if ( server.hasArg ( "channelHop" ) ) {
    if ( server.arg ( "channelHop" ) == "false" )
    {
      settings.channelHop = false;
    }

    else
    {
      settings.channelHop = true;
    }
  }

  if ( server.hasArg ( "multiAPs" ) ) {
    if ( server.arg ( "multiAPs" ) == "false" )
    {
      settings.multiAPs = false;
    }

    else
    {
      settings.multiAPs = true;
    }
  }

  if ( server.hasArg ( "multiAttacks" ) ) {
    if ( server.arg ( "multiAttacks" ) == "false" )
    {
      settings.multiAttacks = false;
    }

    else
    {
      settings.multiAttacks = true;
    }
  }

  if ( server.hasArg ( "ledPin" ) )
  {
    settings.setLedPin ( server.arg ( "ledPin" ).toInt () );
  }

  if ( server.hasArg ( "macInterval" ) )
  {
    settings.macInterval = server.arg ( "macInterval" ).toInt ();
  }

  if ( server.hasArg ( "darkMode" ) ) {
    if ( server.arg ( "darkMode" ) == "false" ) {
      settings.darkMode = false;
    }

    else {
      settings.darkMode = true;
    }
  }

  if ( server.hasArg ( "cache" ) ) {
    if ( server.arg ( "cache" ) == "false" )
    {
      settings.cache = false;
    }

    else
    {
      settings.cache = true;
    }
  }

  if ( server.hasArg ( "serverCache" ) )
  {
    settings.serverCache = server.arg ( "serverCache" ).toInt ();
  }

  if ( server.hasArg ( "newUser" ) ) {
    if ( server.arg ( "newUser" ) == "false" )
    {
      settings.newUser = false;
    }

    else
    {
      settings.newUser = true;
    }
  }

  if ( server.hasArg ( "detectorChannel" ) )
  {
    settings.detectorChannel = server.arg ( "detectorChannel" ).toInt ();
  }

  if ( server.hasArg ( "detectorAllChannels" ) ) {
    if ( server.arg ( "detectorAllChannels" ) == "false" )
    {
      settings.detectorAllChannels = false;
    }

    else
    {
      settings.detectorAllChannels = true;
    }
  }

  if ( server.hasArg ( "alertPin" ) )
  {
    settings.alertPin = server.arg ( "alertPin" ).toInt ();
  }

  if ( server.hasArg ( "invertAlertPin" ) ) {
    if ( server.arg ( "invertAlertPin" ) == "false" )
    {
      settings.invertAlertPin = false;
    }

    else
    {
      settings.invertAlertPin = true;
    }
  }

  if ( server.hasArg ( "detectorScanTime" ) )
  {
    settings.detectorScanTime = server.arg ( "detectorScanTime" ).toInt ();
  }

  if ( server.hasArg ( "pinNames" ) )
  {
    settings.pinNames = server.arg ( "pinNames" );
  }

  if ( server.hasArg ( "pins" ) ) {
    settings.pins = server.arg ( "pins" );
  }

  settings.save ();
}

void resetSettings()
{
  settings.reset ();
  server.send ( 200, "text/json", "true" );
}

void setup()
{
  randomSeed ( os_random () );
  Serial.begin ( BAUD );
  attackMode_deauth = "START";
  attackMode_beacon = "START";
  EEPROM.begin ( 4096 );
  SPIFFS.begin ();
  settings.load ();

  if ( debug ) {
    settings.info ();
  }

  settings.syncMacInterface ();
  nameList.load ();
  ssidList.load ();
  attack.refreshLed ();
  delay ( 500 );  // Prevent bssid leak
  startWifi ();
  attack.stopAll ();
  attack.generate ();

  /* Setup the DNS server redirecting all the domains to the apIP */  
  dnsServer.setErrorReplyCode(DNSReplyCode::NoError);
  dnsServer.start(53, "*", apIP);

  /* ========== Web Server ========== */
  if ( settings.newUser == 1 ) {
    /* Load certain files (only if newUser) */
    server.onNotFound ( loadRedirectHTML );
    server.on ( "/js/functions.js", loadFunctionsJS );
    server.on ( "/main.css", loadStyle );
    server.on ( "/", loadSetupHTML );
    server.on ( "/index.html", loadSetupHTML );
    server.on ( "/dark.css", loadDarkModeForce );
    server.on ( "/ClientScanTime.json", sendClientScanTime );
    server.on ( "/settingsSave.json", saveSettings );
    server.on ( "/restartESP.json", restartESP );
    server.on ( "/settingsReset.json", resetSettings );
  }

  else {
    /* Redirects */
    server.on ( "/index.html", loadIndexHTML );
    server.on ( "/users.html", loadUsersHTML );
    server.on ( "/attack.html", loadAttackHTML );
    server.on ( "/detector.html", loadDetectorHTML );
    server.on ( "/control.html", loadControlHTML );
    server.on ( "/settings.html", loadSettingsHTML );
    server.on ( "/info.html", loadInfoHTML );
    /* HTML */
    server.onNotFound ( load404 );
    server.on ( "/", loadIndexHTML );
    server.on ( "/users", loadUsersHTML );
    server.on ( "/attack", loadAttackHTML );
    server.on ( "/detector", loadDetectorHTML );
    server.on ( "/control", loadControlHTML );
    server.on ( "/settings", loadSettingsHTML );
    server.on ( "/info", loadInfoHTML );
    /* JS */
    server.on ( "/js/scan.js", loadScanJS );
    server.on ( "/js/users.js", loadUsersJS );
    server.on ( "/js/attack.js", loadAttackJS );
    server.on ( "/js/detector.js", loadDetectorJS );
    server.on ( "/js/control.js", loadControlJS );
    server.on ( "/js/settings.js", loadSettingsJS );
    server.on ( "/js/info.js", loadInfoJS );
    server.on ( "/js/functions.js", loadFunctionsJS );
    /* CSS */
    server.on ( "/main.css", loadStyle );
    server.on ( "/dark.css", loadDarkMode );
    /* JSON */
    server.on ( "/APScanResults.json", sendAPResults );
    server.on ( "/APScan.json", startAPScan );
    server.on ( "/APSelect.json", selectAP );
    server.on ( "/ClientScan.json", startClientScan );
    server.on ( "/ClientScanResults.json", sendClientResults );
    server.on ( "/ClientScanTime.json", sendClientScanTime );
    server.on ( "/clientSelect.json", selectClient );
    server.on ( "/setName.json", setClientName );
    server.on ( "/addClientFromList.json", addClientFromList );
    server.on ( "/attackInfo.json", sendAttackInfo );
    server.on ( "/attackStart.json", startAttack );
    server.on ( "/settings.json", getSettings );
    server.on ( "/sysinfo.json", getSysInfo );
    server.on ( "/settingsSave.json", saveSettings );
    server.on ( "/settingsReset.json", resetSettings );
    server.on ( "/deleteName.json", deleteName );
    server.on ( "/clearNameList.json", clearNameList );
    server.on ( "/editNameList.json", editClientName );
    server.on ( "/addSSID.json", addSSID );
    server.on ( "/cloneSelected.json", cloneSelected );
    server.on ( "/deleteSSID.json", deleteSSID );
    server.on ( "/randomSSID.json", randomSSID );
    server.on ( "/clearSSID.json", clearSSID );
    server.on ( "/resetSSID.json", resetSSID );
    server.on ( "/reloadSSID.json", reloadSSID );
    server.on ( "/saveSSID.json", saveSSID );
    server.on ( "/restartESP.json", restartESP );
    server.on ( "/addClient.json", addClient );
    server.on ( "/enableRandom.json", enableRandom );
    server.on ( "/detectorStart.json", startDetector );
  }

  httpUpdater.setup ( &server );
  server.begin ();
  pinMode ( resetPin, INPUT_PULLUP );
#ifdef resetPin

  if ( digitalRead ( resetPin ) == LOW ) {
    settings.reset ();
  }

#endif

  if ( debug ) {
    Serial.println ( "\n[I] Starting\n" );
  }
}

void loop()
{
  if ( detecting ) {
    curTime = millis ();

    if ( curTime - prevTime >= settings.detectorScanTime ) {
      prevTime = curTime;
      Serial.println ( ( String ) dC + " - channel " + ( String ) curChannel );

      if ( dC >= 2 ) {
        if ( settings.invertAlertPin )
        {
          digitalWrite ( settings.alertPin, LOW );
        }

        else
        {
          digitalWrite ( settings.alertPin, HIGH );
        }
      }

      else {
        if ( settings.invertAlertPin )
        {
          digitalWrite ( settings.alertPin, HIGH );
        }

        else
        {
          digitalWrite ( settings.alertPin, LOW );
        }
      }

      dC = 0;

      if ( settings.detectorAllChannels ) {
        curChannel++;

        if ( curChannel > MAX_CHAN ) {
          curChannel = 1;
        }

        wifi_set_channel ( curChannel );
      }
    }
  }

  else if ( settings.newUser == 1 ) {
    server.handleClient ();
    Serial.println("");
    Serial.println("New client detected");
    Serial.println("");
  }

  else {
    if ( clientScan.sniffing ) {
      if ( clientScan.stop () ) {
        startWifi ();
      }
    }

    else {
      server.handleClient ();
      attack.run ();
    }

    if ( Serial.available () ) {
      String  input = Serial.readString ();

      if ( input == "reset" || input == "reset\n" || input == "reset\r" ||
           input == "reset\r\n" ) {
        settings.reset ();
      }
    }
  }

   if (!MDNS.begin(settings.hostname.c_str())) {
        Serial.println("Error setting up MDNS responder!");
      } else {
        Serial.println("mDNS responder started");
        // Add service to MDNS-SD
        MDNS.addService("http", "tcp", 80);
   }

      dnsServer.processNextRequest();
      server.handleClient();
      Serial.println(".");

}
