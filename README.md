# TheWall - HackMyVM (Easy)
 
![TheWall.png](TheWall.png)

## Übersicht

*   **VM:** TheWall
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=TheWall)
*   **Schwierigkeit:** Easy
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 26. Oktober 2022
*   **Original-Writeup:** https://alientec1908.github.io/TheWall_HackMyVM_Easy/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel der "TheWall"-Challenge war die Erlangung von User- und Root-Rechten. Der Weg begann mit der Enumeration eines Webservers (Port 80), auf dem eine PHP-Datei `includes.php` gefunden wurde. Diese Datei war anfällig für Local File Inclusion (LFI) über den Parameter `display_page`. Mittels LFI wurde `/etc/passwd` gelesen, was den Benutzer `john` offenbarte. Anschließend wurde Apache Log Poisoning verwendet: Ein PHP-Reverse-Shell-Payload wurde in die Apache-Logs geschrieben (z.B. durch einen manipulierten User-Agent oder eine ungültige URL-Anfrage) und dann über die LFI-Schwachstelle (`includes.php?display_page=/var/log/apache2/access.log`) ausgeführt, um eine Shell als `www-data` zu erhalten. Als `www-data` wurde eine `sudo`-Regel gefunden, die erlaubte, `/usr/bin/exiftool` als Benutzer `john` auszuführen. Dies wurde genutzt, um den öffentlichen SSH-Schlüssel des Angreifers in `/home/john/.ssh/authorized_keys` zu schreiben, was SSH-Zugriff als `john` ermöglichte. Die User-Flag wurde in dessen Home-Verzeichnis gefunden. Die Privilegieneskalation zu Root erfolgte durch Ausnutzung der Linux Capability `cap_dac_read_search=ep`, die für `/usr/sbin/tar` gesetzt war. Damit konnte der private SSH-Schlüssel von `root` (`/root/.ssh/id_rsa`) archiviert, extrahiert und für einen SSH-Login als `root` verwendet werden.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `curl`
*   `grep`
*   `wfuzz`
*   `base64` (für PHP Payload)
*   `ssh`
*   `nc` (netcat)
*   `script`
*   `stty`
*   `reset`
*   `sudo`
*   `ls`
*   `find`
*   `chmod`
*   `exiftool`
*   `cat`
*   `getcap`
*   `tar`
*   `gobuster`
*   Standard Linux-Befehle (`cd`, `id`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "TheWall" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Web Enumeration (LFI):**
    *   IP-Findung mit `arp-scan` (`192.168.2.113`).
    *   `nmap`-Scan identifizierte offene Ports: 22 (SSH - OpenSSH 8.4p1) und 80 (HTTP - Apache 2.4.54).
    *   Direkter Zugriff auf `/` und `/includes.php` auf Port 80 war verboten (403).
    *   Entdeckung einer Local File Inclusion (LFI)-Schwachstelle in `http://192.168.2.113/includes.php` über den Parameter `display_page`.
    *   Auslesen von `/etc/passwd` via LFI (`?display_page=/etc/passwd`) offenbarte den Benutzer `john`.
    *   `wfuzz` mit LFI-Payloads fand `/var/log/apache2/error.log` (und implizit `access.log`) als lesbar.
    *   User-Flag `cc5db5e7b0a26e807765f47a006f6221` für `john` wurde via LFI aus `/home/john/user.txt` gelesen.

2.  **Initial Access (LFI & Log Poisoning zu `www-data`):**
    *   Vorbereitung eines PHP-Reverse-Shell-Payloads.
    *   Einschleusen des PHP-Payloads in die Apache-Logs (z.B. `/var/log/apache2/access.log`) durch einen präparierten HTTP-Request (z.B. mit dem Payload im User-Agent oder als Teil einer ungültigen URL).
    *   Ausführung des Payloads durch Aufruf der Logdatei über die LFI-Schwachstelle (`http://192.168.2.113/includes.php?display_page=/var/log/apache2/access.log`). Im Log wurde dies über eine Webshell (`cmd`-Parameter in der LFI-URL) erreicht, die zuvor in den Log geschrieben wurde.
    *   Erlangung einer interaktiven Reverse Shell als `www-data` nach Stabilisierung.

3.  **Privilege Escalation (von `www-data` zu `john` via `sudo exiftool`):**
    *   `sudo -l` als `www-data` zeigte: `(john : john) NPASSWD: /usr/bin/exiftool`.
    *   Generierung eines SSH-Schlüsselpaars auf der Angreifer-Maschine.
    *   Hochladen des öffentlichen Schlüssels des Angreifers auf das Ziel (z.B. `/tmp/authorized_keys`).
    *   Ausnutzung von `exiftool` zum Schreiben des öffentlichen Schlüssels in `/home/john/.ssh/authorized_keys`: `sudo -u john /usr/bin/exiftool -filename=/home/john/.ssh/authorized_keys /tmp/authorized_keys` (oder ähnliche `exiftool`-Technik).
    *   Erfolgreicher SSH-Login als `john` mit dem privaten Schlüssel des Angreifers.

4.  **Privilege Escalation (von `john` zu `root` via `tar` Capability):**
    *   `/usr/sbin/getcap -r / 2>/dev/null` als `john` zeigte, dass `/usr/sbin/tar` die Capability `cap_dac_read_search=ep` besaß.
    *   Ausnutzung der Capability zum Lesen des privaten SSH-Schlüssels von `root`:
        1.  `/usr/sbin/tar -czf id_rsa.tar /root/.ssh/id_rsa` (archiviert den Root-Schlüssel).
        2.  `tar -xf id_rsa.tar` (entpackt den Schlüssel in `john`s aktuellem Verzeichnis).
    *   Erfolgreicher SSH-Login als `root` mit dem extrahierten privaten Schlüssel (`ssh root@localhost -i id_rsa`).
    *   Root-Flag `4be82a3be9aed6eea5d0cce68e17662e` in `/root/r0t.txT` gelesen.

## Wichtige Schwachstellen und Konzepte

*   **Local File Inclusion (LFI):** Die Datei `includes.php` erlaubte das Einbinden und Anzeigen beliebiger lokaler Dateien.
*   **Apache Log Poisoning:** Einschleusen von PHP-Code in Apache-Logdateien und anschließende Ausführung über die LFI-Schwachstelle.
*   **Unsichere `sudo`-Konfiguration (`exiftool`):** Die Erlaubnis, `exiftool` als anderer Benutzer auszuführen, ermöglichte das Schreiben von Dateien (hier `authorized_keys`) im Kontext dieses Benutzers.
*   **Linux Capabilities (`cap_dac_read_search` auf `tar`):** Das `tar`-Binary besaß eine Capability, die es erlaubte, Dateiberechtigungen beim Lesen zu umgehen, was das Auslesen des Root-SSH-Schlüssels ermöglichte.
*   **Auslesen privater SSH-Schlüssel:** Ermöglichte passwortlosen Login als die betroffenen Benutzer (`john`, `root`).

## Flags

*   **User Flag (`/home/john/user.txt`):** `cc5db5e7b0a26e807765f47a006f6221`
*   **Root Flag (`/root/r0t.txT`):** `4be82a3be9aed6eea5d0cce68e17662e`

## Tags

`HackMyVM`, `TheWall`, `Easy`, `LFI`, `Log Poisoning`, `RCE`, `sudo Exploitation`, `exiftool`, `Linux Capabilities`, `cap_dac_read_search`, `tar`, `SSH`, `Privilege Escalation`, `Linux`, `Web`
