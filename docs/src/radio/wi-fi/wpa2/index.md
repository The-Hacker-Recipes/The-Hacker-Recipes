---
authors: ShutdownRepo
category: radio
---

# 🛠️ WPA2

## Theory



## Attacks

//TODO : differences between CCMP and TKIP for cipher ? 

### Sniffing

![](./assets/sniffing.png){.rawimg}


### De-authentication

![](./assets/deauth.png){.rawimg}

### WPA handshake capture & cracking

clients needed

sniffing + deauth

gives "WPA handshake" followed by AP MAC addr, possible to crack

![](./assets/wpahandshake.png){.rawimg}

either crack with aircrack directly or use aircrack to create a hashcat formatted file

![](./assets/aircrack_crack.png){.rawimg}

preparing hashcat file

![](./assets/aircrack_hashcat.png){.rawimg}

cracking

![](./assets/hashcat.png){.rawimg}

### PMKID capture



### KRACK



## Resources