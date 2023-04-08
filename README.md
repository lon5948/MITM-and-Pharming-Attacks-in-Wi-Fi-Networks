# MITM-and-Pharming-Attacks-in-Wi-Fi-Networks

### Man-in-the-middle attack
- obtain all other client devices’ IP/MAC addresses in a connected Wi-Fi network
- ARP spoofing for all other client devices in the Wi-Fi network
- split SSL/TLS encrypted sessions and get the inputted username/password strings from HTTPS sessions

### Pharming attack
- Obtain all other client devices’ IP/MAC addresses in a connected Wi-Fi network
- DNS spoofing attack for web services

### Run

compile 
```
make
```

MITM attack
```
sudo ./mitm_attack
```

Pharming attack
```
sudo ./pharm_attack
```
