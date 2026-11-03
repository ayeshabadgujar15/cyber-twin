# Forensics practical setup

## Volatility 3

Installed version: 2.28.2. Startup and help output verified.

In PowerShell, run:

```powershell
& 'D:\cyber-twin\practical-tools\vol.cmd' -h
& 'D:\cyber-twin\practical-tools\vol.cmd' -f 'C:\path\memory.dmp' windows.info
```

The correct package installation command is `python -m pip install volatility3`.

## Wireshark

Wireshark 4.6.9 and Npcap 1.89 are installed. Network interface enumeration was verified. Open Wireshark from Start and choose the Wi-Fi interface for a live capture, or File > Open for a supplied capture file.

## Kali and Plaso

WSL components and Kali Linux Rolling reported successful installation. Windows explicitly requires a restart before the changes take effect. Save your work and restart. Open Kali Linux from Start and create your Linux username and password. Password typing is invisible, which is normal. Kali package updates and Plaso installation have not yet run.

After Kali starts, run:

```sh
sh /mnt/d/cyber-twin/practical-tools/finish-kali.sh
```

This updates Kali and installs Plaso. To inspect help:

```sh
plaso-log2timeline -h
plaso-psort -h
```

## Splunk

Splunk Enterprise 10.6.0.5 was installed to `D:\Splunk`. Its Windows service is running and its login page returned HTTP 200 at http://localhost:8000/en-US/account/login . The administrator username is `admin`; the generated password is saved locally in `D:\Splunk-login.txt`.

The file `installers/splunk-10.6.0.5-x64.msi` is incomplete; do not run it.

## Autopsy

Autopsy 4.23.1 is registered as installed at `C:\Program Files\Autopsy-4.23.1\`. The downloaded installer has a valid Sleuth Kit Labs signature and matches the Windows installer catalog SHA256 checksum. Open Autopsy from Start after restarting Windows. Its graphical startup has not been verified.
