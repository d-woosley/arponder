# arponder
```text
   _____ ____________________                 _           
  /  _  \\______   \\______  \               | |          
 /  /_\  \|       _/|     ___/ ___  _ __   __| | ___ _ __ 
/    |    \    |   \|    |    / _ \| '_ \ / _` |/ _ \ '__|
\____|__  /____|_  /|____|   | (_) | | | | (_| |  __/ |   
        \/       \/           \___/|_| |_|\__,_|\___|_|    
```
A Modern Layer-2 Attack Toolkit... one day. Right now it just checks for ARP spoofing protections.

## Use
```bash
sudo ./arponder.py check -I <Network Interface> [-t <Timeout>]
```

### Example
```bash
sudo ./arponder.py -I eht0 -t 10
```


## To-do
 - Add in auto ARP poisoning agaist stale ARP
 - Do the rest of the whole "Modern Layer-2 Attack Toolkit" thing.
