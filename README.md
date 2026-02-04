# Oracle Database 26ai on Amazon EC2

<img width="1188" height="766" alt="Screenshot 2026-02-04 at 11 10 52 AM" src="https://github.com/user-attachments/assets/4276d58c-669b-433f-a3de-ffefe087fdb4" />

This repository documents a **step-by-step installation guide for Oracle Database 26ai on Amazon EC2**, following an on‑prem–style deployment model with AWS best practices for compute, storage, networking, and licensing.

The approach is suitable for **Enterprise licensed environments** as well as **Oracle Database 26ai Free** for labs and proofs of concept.

---

## Scope

- Platform: Amazon EC2
- Operating System: Oracle Linux 8 or 9 (Oracle Linux 9 recommended)
- Database: Oracle Database 26ai
- Deployment model: Manual installation on EC2 (no RDS)
- Architecture: Multitenant (CDB + PDB)

---

## 1. Installation Approaches on AWS

There are three possible ways to run Oracle Database 26ai on EC2:

1. **EC2 + Oracle Linux + manual installation (recommended)**  
   - Closest to on‑prem best practices
   - Full control over storage, networking, and patching

2. **EC2 using an Oracle Marketplace AMI**  
   - Currently available for earlier releases (e.g., 23ai Free)
   - Expected to appear for 26ai in the future

3. **Oracle Database 26ai Free in containers (Docker/Podman)**  
   - Suitable only for labs and development

For production‑grade environments, the recommended approach is:

> **EC2 + Oracle Linux 9 + classic Oracle installation (RPM or OUI)**

<img width="1590" height="782" alt="Screenshot 2026-02-04 at 10 00 01 AM" src="https://github.com/user-attachments/assets/8f32374c-ec7a-40f3-a778-f26e9a332944" />

---

## 2. EC2 Instance Provisioning

### 2.1 Instance Type

Choose an **EBS‑optimized** instance family:

- `m6i / m7i` – general purpose workloads
- `r6i / r7i` – memory‑intensive databases

Example starting point:
- `m6i.xlarge` (4 vCPU, 16 GB RAM)

### 2.2 AMI

- Oracle Linux 9 (official AMI)
- UEK kernel recommended

### 2.3 Storage Layout (EBS)

Use **separate EBS volumes** for performance and manageability:

| Purpose | Mount point | Volume type |
|------|------------|-------------|
| Operating System | `/` | gp3 |
| Oracle software | `/u01` | gp3 |
| Datafiles | `/u02` | gp3 or io1 |
| Redo logs | `/u03` | gp3 or io1 |
| FRA / backups | `/u04` | gp3 |

---

## 3. Networking and Security

### 3.1 Security Group Rules

Open only the required ports:

| Port | Purpose | Source |
|----|-------|-------|
| 22 | SSH | Admin IP / VPN |
| 1521 | Oracle Listener | Authorized CIDR |

### 3.2 Network Design

- Private subnet recommended
- Bastion host for administration
- Internal DNS enabled

---

## 4. Operating System Preparation (Oracle Linux 9)

<img width="1115" height="840" alt="Screenshot 2026-02-04 at 9 59 33 AM" src="https://github.com/user-attachments/assets/e8ef0700-e387-4901-b55d-c2178755a982" />


Update the system:

```bash
sudo dnf update -y
```

Install the Oracle 26ai preinstall package:

```bash
sudo dnf -y install oracle-ai-database-preinstall-26ai
```

This package configures:
- `oracle` user and groups
- Kernel parameters
- System limits
- Required OS dependencies

---

## 5. Oracle Directory Structure

Create standard Oracle directories:

```bash
sudo mkdir -p /u01/app/oracle/product/26ai/dbhome_1
sudo mkdir -p /u02/oradata
sudo chown -R oracle:oinstall /u01 /u02
sudo chmod -R 775 /u01 /u02
```

---

## 6. Installing Oracle Database 26ai

### Option A: RPM Installation (Oracle Database 26ai Free – Labs)

Install the RPM:

```bash
sudo dnf -y install oracle-ai-database-free-26ai-23.26.0-1.el9.x86_64.rpm
```

Run the configuration script:

```bash
sudo /etc/init.d/oracle-free-26ai configure
```

This automatically creates:
- CDB: `FREE`
- PDB: `FREEPDB1`
- Listener on port 1521

---

### Option B: Classic Installation (Enterprise / Standard Edition)

As user `oracle`:

```bash
su - oracle
unzip LINUX.X64_26AI_DB_HOME.zip -d /u01/app/oracle/product/26ai/dbhome_1
cd /u01/app/oracle/product/26ai/dbhome_1
./runInstaller
```

Silent installation is also supported for EC2 automation.

---

## 7. Database Creation

Use DBCA (GUI or silent mode):

```bash
dbca
```

Recommended settings:
- Multitenant architecture (CDB + PDB)
- Character set: `AL32UTF8`
- Datafiles under `/u02/oradata`
- FRA on a separate volume

---

## 8. Post‑Installation Configuration

### 8.1 Oracle Environment Variables

Update `~oracle/.bash_profile`:

```bash
export ORACLE_BASE=/u01/app/oracle
export ORACLE_HOME=/u01/app/oracle/product/26ai/dbhome_1
export ORACLE_SID=ORCL
export PATH=$ORACLE_HOME/bin:$PATH
```

### 8.2 Validation

Local connection:

```bash
sqlplus / as sysdba
```

Remote connection:

```bash
sqlplus sys@<ec2-hostname>:1521/<service_name> as sysdba
```

---

## 9. Licensing and AWS Best Practices

### 9.1 Licensing

- EC2 is considered a **third‑party cloud**
- Oracle licenses are **BYOL**
- vCPU counting must follow Oracle cloud licensing policies

### 9.2 Operational Best Practices

- Use EBS‑optimized instances
- Separate volumes for DATA, REDO, and FRA
- Backups using RMAN
- Store backups outside the instance (EBS snapshots or S3)
- Monitor with CloudWatch and OS tools

---

## 10. Recommended Architecture Summary

![OracleOnEC2-Pattern-1-1 (1)](https://github.com/user-attachments/assets/d154990f-9501-4ff0-b4f8-8e720e026795)


- Dedicated EC2 instance
- Oracle Linux 9
- Oracle Database 26ai (CDB + PDB)
- EBS gp3 / io1 volumes
- Minimal network exposure
- Externalized backups

---

## 11. CloudFormation Automation

<img width="1170" height="357" alt="Screenshot 2026-02-04 at 6 23 30 PM" src="https://github.com/user-attachments/assets/1eaebba1-8cc6-4e88-8132-078a70a09882" />


- Deploy the CloudFormation stack defined in **oracle-26ai-ec2-improved.yaml**.

---

## Next Steps

Possible extensions:
- Region‑specific deployment scripts (e.g. `us-east-1`)
- Enterprise Edition tuning
- High‑performance EBS layouts
- Licensing and audit readiness checklist

---

**Author:** Sebas Jaramillo

