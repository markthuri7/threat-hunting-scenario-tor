
<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/markthuri7/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2026-03-28T04:31:50Z`. These events began at `2026-03-28T03:57:23.5592363Z`.

**Query used to locate events:**

```kql
DeviceFileEvents  
| where DeviceName == "windows-11-vm-e"  
| where InitiatingProcessAccountName == "markmthus"  
| where FileName contains "tor"  
| where Timestamp >= datetime(2024-11-08T22:14:48.6065231Z)  
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="2004" height="1006" alt="1" src="https://github.com/user-attachments/assets/08095ec2-df61-45f5-a831-7491ecac29d2" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-15.0.8.exe". Based on the logs returned, at `2026-03-28T04:01:28.9973851Z`, an employee on the "markmthus" device ran the file `tor-browser-windows-x86_64-portable-15.0.8.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents  
| where DeviceName == "windows-11-vm-e"  
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.8.exe"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1982" height="774" alt="2" src="https://github.com/user-attachments/assets/2c634ef1-2aeb-4f1f-94ce-8f9a1e45c473" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "markmthus" actually opened the TOR browser. There was evidence that they did open it at `2026-03-28T04:03:02.985053`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "windows-11-vm-e"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img width="2064" height="994" alt="4" src="https://github.com/user-attachments/assets/22a234ad-f823-46e3-89dc-f5d8051c995d" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2026-03-28T04:04:15.7934745Z`, an employee on the "windows-11-vm-e" device successfully established a connection to the remote IP address `131.203.32.146 ` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\markmthus\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "windows-11-vm-e"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="2054" height="1020" alt="6" src="https://github.com/user-attachments/assets/cc6e829a-ac36-4698-b01a-007a31bb613c" />


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2026-03-28T03:57:23.5592363Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-15.0.8.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\markmthus\Downloads\tor-browser-windows-x86_64-portable-15.0.8.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2026-03-28T04:01:28.9973851Z`
- **Event:** The user "markmthus" executed the file `tor-browser-windows-x86_64-portable-15.0.8.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.8.exe /S`
- **File Path:** `C:\Users\markmthus\Downloads\tor-browser-windows-x86_64-portable-15.0.8.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2026-03-28T04:03:02.9850533Z`
- **Event:** User "markmthus" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\markmthus\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2026-03-28T04:04:15.7934745Z`
- **Event:** A network connection to IP `131.203.32.146` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\markmthus\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2026-03-28T04:04:19Z` - Connected to `64.65.62.79` on port `443`.
  - `2026-03-28T04:04:31Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2026-03-28T04:31:50Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\markmthus\Desktop\tor-shopping-list.txt`

---

## Summary

The user "markmthus" on the "windows-11-vm-e" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `windows-11-vm-e` by the user `markmthus`. The device was isolated, and the user's direct manager was notified.

---
