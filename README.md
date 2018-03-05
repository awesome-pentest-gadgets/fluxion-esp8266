<p align="center"><img src="https://assets-cdn.github.com/favicon.ico" width=24 height=24/>
<p align="center"><a href="https://github.com/FluxionNetwork/fluxion-esp8266">Fluxion-esp8266 </a>a cheap wifi cracker</p>

---

![Fuxion logo](https://github.com/FluxionNetwork/fluxion-esp8266/raw/master/logos/logo.jpg)

# Fluxion is the future of MITM WPA attacks

Fluxion is a security auditing and social-engineering research tool. It is a remake of linset by vk496 with (hopefully) less bugs and more functionality. The script attempts to retrieve the WPA/WPA2 key from a target access point by means of a social engineering (phising) attack.If you need quick help, fluxion is also avaible on gitter. You can talk with us [here](https://gitter.im/FluxionNetwork/Lobby)

## Fluxion on the esp8266 
This modified fimrware allows not only to perform deauth attacks using the ESP8266 against selected networks. 
You could also run in the meantime a captive portal.
 Because it is really cheap and very easy to use it makes this attack so effective. <br> <br>
The ESP8266 has a build in SoC which is programmable using your Arduino.  
I modifyed [spacehuhn](https://github.com/spacehuhn/esp8266_deauther) existing project and add a couple of features which I missed such as a working redirection to the portal site or a DNS resolver.

### Deauth attacks
The deauth attack will, if the connection is vulnerable, disconnect the devices from the network. Because the attack is running constantly, the devices will be disconnected again and again. Depending on the network, that can either block a connection or slow it down.


The deauth attack works by exploiting an old and known vulnerability in the 802.11 Wi-Fi protocol.
Because these deauthentication frames, usually used to close a Wi-Fi connection safely, are unencrypted, it's very easy to spoof them. You only need the mac address of the access point, which you can sniff easily.
If you don't want to attack all connected devices, you can also scan for connections and attack them specifically.

### Attacks
* Deauth attack
* Captive portal
* Beacon and probe request flooding

## How to protect
Protection against deauth attacks is not so easy.
 With the 802.11w-2009 the WiFi protocol became encrypted management (and deauthentication) frames.
 This makes spoofing these packets way harder and the attack, in this form, ineffective.
Use a router which support these protocol.
If it doesn't support it yet the vendor maybe include this in newer firmware or you could use an custom firmware for your router like OpenWRT.

Using the 802.11w-2009 protocol it is required that both systems support this.
You could also build your own router which is recommended since nearly every "plastic router" is vulnerable. 

## Supported Devices
I use the NodeMCU but you could also use another device. I like the NodeMcu because it is very easy to use it doesn't require much wires and you don't need a programmer since it is on the chip.
Thats why I go with the NodeMCU Lua Lolin V3 Module. For this type of chip it is not very cheap and if you have an programmer already you should only buy the chip without any module. Thus are new I would recommend these one. You can buy them on amazon.

## Installation
You only need to do 1 of the given installation methods.

### Methode 1: For beginners recommended
Installation is very simple if you use a precompiled version. You only need to flash the the ```bin``` file using the esp flash tool:

1. Upload the ```bin``` using the esp flash tool of your choice
	* nodemcu-flasher
	* esptool-gui
	* esptool

2. Thats all 

Make sure you change all the required settings and follow the instructions. Sometimes the flash process start not automatically, you have to press the `flash` button. Use this combination if it is not working.

1. Press the `Reset` Button for 10 seconds.
2. Press the `Flash` Button in combination with the `Reset` Button for 5 seconds
3. Release the `Flash` Button
4. Release the `Reset` Button 

### Methode 2: For developers
1. Download the source code of the project or clone it with<br>
`git clone https://www.github.com/FluxionNetwork/fluxion-esp8266`

2. Go to `File` -> `Preferences` and add<br>
`http://arduino.esp8266.com/stable/package_esp8266com_index.json` <br> to the additional boards manager URLs.

3. Go to `Tools` -> `Board` -> `Boards Manager`

4. Type in `esp8266` and select version `2.0.0` and click on `Install`

5. Go to `File` -> `Preferences`

6. Open the folder path under `More preferences can be edited directly in the file`

7. Copy the `user_interface.h` inside the `misc/sdk_fix` folder to <br>
`packages` -> `esp8266` -> `hardware` -> `esp8266` -> `2.0.0`- > `tools` -> `sdk` -> `include`

8. Copy  `ESP8266Wi-Fi.cpp` and  `ESP8266Wi-Fi.h` to <br>
`packages` -> `esp8266` -> `hardware` -> `esp8266` -> `2.0.0` -> `libraries`-> `ESP8266WiFi` -> `src`

9. Depending on your board make adjustments and make sure the settings are correct e.g.
	* Flash size 
	* Board type
	* Flash frequenz

## :scroll: Changelog
Fluxion gets weekly updates with new features, improvements, and bugfixes.
Be sure to check out the [changelog](https://github.com/FluxionNetwork/fluxion-esp8266/commits/master).

## :book: How it works
This is how the original fluxion attack work. The esp8266 version works slightly different.

* Scan for a target wireless network.
* Launch the `Handshake Snooper` attack.
* Capture a handshake (necessary for password verification).
* Launch `Captive Portal` attack.
* Spawns a rogue (fake) AP, imitating the original access point.
* Spawns a DNS server, redirecting all requests to the attacker's host running the captive portal.
* Spawns a web server, serving the captive portal which prompts users for their WPA/WPA2 key.
* Spawns a jammer, deauthenticating all clients from original AP and luring them to the rogue AP.
* All authentication attempts at the captive portal are checked against the handshake file captured earlier.
* The attack will automatically terminate once a correct key has been submitted.
* The key will be logged and clients will be allowed to reconnect to the target access point.


## :heavy_exclamation_mark: Requirements
### Methode 1 
This Methode requires not very much exept:

* esp8266 chip
* flash tool
* usb cable

### Methode 2
Additional it require:

* Arduino IDE
* Esp8266 libary 

## Related work
For development I use a combination of vim, nvim and tmux. For everyone who is interested here are my [dotfiles](https://github.com/deltaxflux/takumi/).
They are really clean and I do all my best to improve these.

## :octocat: Credits
Thanks for all hard work to [spacehuhn](https://github.com/spacehuhn/). He does really good work here and most of the source code is from him so defintly take a look at him.
## Disclaimer
* Authors do not own the logos under the `/attacks/Captive Portal/sites/` directory. Copyright Disclaimer Under Section 107 of the Copyright Act 1976, allowance is made for "fair use" for purposes such as criticism, comment, news reporting, teaching, scholarship, and research.
* The usage of Fluxion to attack infrastructure without prior mutual consent could be considered an illegal activity, and is highly discouraged by its authors and developers. It is the end users responsibility to obey all applicable local, state and federal laws. Authors assume no liability and are not responsible for any misuse or damage caused by this program.

## Additional links
* deauth attack: <br>`https://en.wikipedia.org/wiki/Wi-Fi_deauthentication_attack` 
* deauth frame:<br> `https://mrncciew.com/2014/10/11/802-11-mgmt-deauth-disassociation-frames/`

## Contribution

Please report issues/bugs, feature requests and suggestions for improvements to the [issue tracker](https://github.com/FluxionNetwork/fluxion-esp8266/issues).

<p align="center"><img src="https://camo.githubusercontent.com/ba40cf893a8f6dcdc5d1db437564f634f3ca0b4a/68747470733a2f2f63646e2e7261776769742e636f6d2f61726374696369636573747564696f2f6e6f72642f646576656c6f702f7372632f6173736574732f62616e6e65722d666f6f7465722d6d6f756e7461696e732e737667" /></p>
<p align="center"><p align="center"https://img.shields.io/aur/license/yaourt.svg"/></p>
