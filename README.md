# oracle-database-26ai-amazon-ec2-installation-guide
Guia de Instalacion Oracle Database 26ai en Amazon EC2


Guía de instalación de Oracle Database 26ai en Amazon EC2

Alcance

Plataforma: Amazon EC2

Sistema operativo: Oracle Linux 8 u 9 (recomendado OL9)

Base de datos: Oracle Database 26ai

Modalidad: instalación clásica (RPM / OUI), no contenedores

Uso: Enterprise / Standard / Free (lab)

1. Selección del enfoque en AWS

Para un entorno serio y alineado con best practices:

Opción recomendada

EC2 + Oracle Linux 9 + instalación clásica (RPM u OUI)

Otras opciones (no foco de esta guía)

AMI del Marketplace con Oracle preinstalado (cuando exista para 26ai)

Contenedores Oracle 26ai Free (solo labs)

2. Creación de la instancia EC2
2.1 Tipo de instancia

Selecciona una familia EBS-optimized según la carga esperada:

m6i / m7i → carga general

r6i / r7i → bases intensivas en memoria

Ejemplo recomendado inicial:

m6i.xlarge (4 vCPU, 16 GB RAM)

2.2 AMI

Oracle Linux 9 (OL9) – AMI oficial

Kernel UEK recomendado

2.3 Almacenamiento (EBS)

Separar volúmenes:

Uso	Punto de montaje	Tipo
OS	/	gp3
Software Oracle	/u01	gp3
Datafiles	/u02	gp3 / io1
Redo Logs	/u03	gp3 / io1
FRA / backups	/u04	gp3
3. Red y seguridad
3.1 Security Group

Abrir solo lo necesario:

Puerto	Origen
22 (SSH)	Tu IP / VPN
1521 (Listener)	Rango autorizado
3.2 Networking

Subnet privada + bastion (recomendado)

DNS interno habilitado

4. Preparación del sistema operativo (OL9)

Conéctate por SSH como ec2-user y eleva privilegios:

sudo -i

4.1 Actualizar sistema
dnf update -y

4.2 Instalar paquete preinstall de 26ai

Este paquete configura:

Usuario/grupos oracle

Kernel parameters

Límites de sistema

Dependencias

dnf -y install oracle-ai-database-preinstall-26ai


Verifica:

id oracle
sysctl -a | grep shm

5. Preparación de filesystem Oracle

Ejemplo estándar:

mkdir -p /u01/app/oracle/product/26ai/dbhome_1
mkdir -p /u02/oradata
chown -R oracle:oinstall /u01 /u02
chmod -R 775 /u01 /u02

6. Instalación de Oracle Database 26ai
6.1 Descarga del software

Desde Oracle Software Delivery Cloud:

Oracle Database 26ai for Linux x86-64 (.zip o .rpm)

Copiar el software a la instancia (SCP o S3).

6.2 Instalación – opción A: RPM (recomendado para labs / Free)

Ejemplo Oracle Database 26ai Free:

dnf -y install oracle-ai-database-free-26ai-23.26.0-1.el9.x86_64.rpm


Ejecutar configuración inicial:

/etc/init.d/oracle-free-26ai configure


Esto crea automáticamente:

CDB: FREE

PDB: FREEPDB1

Listener en puerto 1521

6.3 Instalación – opción B: Instalación clásica (Enterprise / Standard)

Como usuario oracle:

su - oracle
unzip LINUX.X64_26AI_DB_HOME.zip -d /u01/app/oracle/product/26ai/dbhome_1


Ejecutar OUI:

./runInstaller


(Opción silent también válida en EC2)

7. Creación de la base de datos

Con DBCA (GUI o silent):

dbca


Buenas prácticas:

Arquitectura CDB + PDB

Charset: AL32UTF8

Datafiles en /u02/oradata

FRA separado

8. Post-instalación
8.1 Variables de entorno (oracle)

Editar ~/.bash_profile:

export ORACLE_BASE=/u01/app/oracle
export ORACLE_HOME=/u01/app/oracle/product/26ai/dbhome_1
export ORACLE_SID=ORCL
export PATH=$ORACLE_HOME/bin:$PATH

8.2 Pruebas

Conexión local:

sqlplus / as sysdba


Conexión remota:

sqlplus sys@ec2-hostname:1521/servicename as sysdba

9. Consideraciones críticas en AWS
9.1 Licenciamiento

EC2 = nube de terceros

Contabilizar vCPU según política Oracle vigente

BYOL (Bring Your Own License)

9.2 Buenas prácticas

Instancias EBS-optimized

Volúmenes separados para DATA / REDO / FRA

Backups con RMAN a:

EBS snapshot

S3 (via NFS gateway o backup plugin)

CloudWatch para monitoreo base

10. Resumen de arquitectura recomendada

EC2 dedicado

Oracle Linux 9

Oracle Database 26ai (CDB + PDB)

EBS gp3/io1

Backups fuera de la instancia

Seguridad mínima necesaria
