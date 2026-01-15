# Network Spoofer Pro - Multi-Host Edition

![Version](https://img.shields.io/badge/version-2.0-blue)
![Python](https://img.shields.io/badge/python-3.8+-green)
![License](https://img.shields.io/badge/license-Educational-orange)

## ⚠️ ADVERTENCIA IMPORTANTE

**Esta herramienta es SOLO para fines educativos y pruebas de penetración autorizadas.**

El uso de esta herramienta sin autorización explícita es **ILEGAL** y puede resultar en consecuencias legales graves. Solo debe usarse en:

- Redes de las que eres propietario
- Entornos de prueba controlados
- Auditorías de seguridad con autorización por escrito
- Propósitos educativos en laboratorios aislados

## 📋 Descripción

Network Spoofer Pro es una herramienta avanzada de ARP/DNS Spoofing que permite realizar ataques Man-in-the-Middle (MITM) en múltiples hosts simultáneamente. Desarrollada con fines educativos para enseñar sobre:

- Vulnerabilidades de la red
- Ataques ARP Poisoning
- DNS Spoofing
- Interceptación de tráfico
- Técnicas de defensa

## ✨ Características Principales

### 🎯 Ataque Multi-Host
- **Selección múltiple**: Ataca varios hosts simultáneamente
- **Gestión individual**: Control independiente de cada host
- **Estadísticas por host**: Monitoreo detallado de cada objetivo

### 🔍 Escaneo de Red
- Detección automática de hosts activos
- Obtención de direcciones MAC
- Interfaz visual con checkboxes
- Selección/deselección masiva

### 🌐 DNS Spoofing Avanzado
- Configuración de múltiples dominios
- Redirección personalizada
- Interceptación en tiempo real
- Logs detallados de consultas

### 📊 Monitoreo y Estadísticas
- Dashboard de estadísticas en tiempo real
- Contador de paquetes ARP/DNS
- Seguimiento de actividad por host
- Exportación de datos a JSON

### 🛠️ Herramientas Adicionales
- **Interceptor de Credenciales**: Captura credenciales HTTP/FTP
- **Monitor de Tráfico**: Visualización de tráfico en tiempo real
- **Bloqueo de Internet**: Desconexión selectiva de hosts

### 📝 Sistema de Logs
- Logs detallados con timestamps
- Exportación a archivos de texto
- Filtrado y búsqueda
- Historial de eventos

## 🚀 Instalación

### Requisitos del Sistema

- **Sistema Operativo**: Linux (Ubuntu/Debian/Kali recomendados)
- **Python**: 3.8 o superior
- **Permisos**: Root/Administrador

### Dependencias

```bash
# Instalar dependencias del sistema
sudo apt-get update
sudo apt-get install python3 python3-pip python3-tk

# Instalar librerías de Python
sudo pip3 install scapy netifaces
```

### Instalación desde requirements.txt

```bash
pip3 install -r requirements.txt
```

## 💻 Uso

### Inicio de la Aplicación

```bash
# Con permisos de administrador (REQUERIDO)
sudo python3 network_spoofer_pro.py

# O hacerlo ejecutable
chmod +x network_spoofer_pro.py
sudo ./network_spoofer_pro.py
```

### Flujo de Trabajo Típico

1. **Escanear la Red**
   ```
   Tab "Escaneo de Red" → Clic en "Escanear Red"
   ```

2. **Seleccionar Hosts Objetivo**
   ```
   Marcar checkboxes de los hosts que deseas atacar
   ```

3. **Configurar DNS Spoofing**
   ```
   Tab "Ataque Multi-Host" → Introducir dominios
   Ejemplo: facebook.com, google.com, twitter.com
   ```

4. **Especificar IP de Redirección**
   ```
   Introducir IP manualmente o usar "Usar mi IP"
   ```

5. **Iniciar Ataque**
   ```
   Clic en "Iniciar Ataque Multi-Host"
   ```

6. **Monitorear**
   ```
   Tab "Estadísticas" → Ver métricas en tiempo real
   Tab "Logs" → Revisar eventos detallados
   ```

7. **Detener Ataque**
   ```
   Clic en "Detener Ataque" para restaurar ARP
   ```

## 📖 Guía de Funcionalidades

### 1. Ataque ARP/DNS Spoofing

**¿Qué hace?**
- Envenenamiento bidireccional de tabla ARP
- Interceptación de consultas DNS
- Redirección de tráfico web

**Casos de uso:**
- Demostrar vulnerabilidades de ARP
- Probar sistemas de detección de MITM
- Educación en seguridad de redes

### 2. Bloqueo de Internet

**¿Qué hace?**
- Envenenamiento unidireccional de ARP
- Bloquea el acceso a internet del host

**Casos de uso:**
- Pruebas de disponibilidad
- Demostrar impacto de ataques DoS
- Control de acceso temporal

### 3. Interceptor de Credenciales

**¿Qué hace?**
- Captura tráfico HTTP/FTP
- Busca patrones de autenticación
- Registra posibles credenciales

**Casos de uso:**
- Demostrar peligros de HTTP sin cifrar
- Educar sobre importancia de HTTPS
- Auditorías de seguridad

### 4. Monitor de Tráfico

**¿Qué hace?**
- Visualiza tráfico en tiempo real
- Filtra por protocolo (HTTP, HTTPS, DNS)
- Muestra origen y destino

**Casos de uso:**
- Análisis de tráfico de red
- Debugging de aplicaciones
- Educación sobre protocolos

## 🔧 Arquitectura del Código

### Estructura de Clases

```python
NetworkSpooferPro
├── __init__()              # Inicialización de la aplicación
├── crear_interfaz()        # Construcción de la GUI
├── escanear_red()          # Descubrimiento de hosts
├── iniciar_ataque()        # Gestión de ataques
├── arp_spoof_thread()      # Thread de ARP spoofing
├── dns_sniff_thread()      # Thread de DNS spoofing
└── actualizar_estadisticas() # Métricas en tiempo real

Host
├── ip                      # Dirección IP del host
├── mac                     # Dirección MAC del host
├── activo                  # Estado del ataque
├── paquetes_enviados      # Contador de paquetes ARP
├── paquetes_interceptados # Contador de paquetes DNS
└── hilo_arp               # Thread dedicado
```

### Flujo de Datos

```
Usuario → Interfaz → NetworkSpooferPro → Threads → Scapy → Red
                          ↓
                    Estadísticas
                          ↓
                        Logs
```

## 📊 Mejoras Implementadas vs Versión Anterior

| Característica | Versión Anterior | Network Spoofer Pro |
|----------------|------------------|---------------------|
| Hosts simultáneos | 1 | Ilimitados |
| Interfaz | Básica | Multi-tab profesional |
| Selección de hosts | Manual | Checkboxes visuales |
| Estadísticas | Limitadas | Completas por host |
| Logs | Básicos | Avanzados con timestamps |
| Exportación | No | JSON y TXT |
| Herramientas extra | 1 | 3+ (Creds, Monitor, Config) |
| Arquitectura | Monolítica | Orientada a objetos |
| Threads | Básico | Gestión avanzada |
| UI/UX | Simple | Profesional con estilos |

## 🛡️ Defensa Contra Estos Ataques

### Prevención de ARP Spoofing

1. **ARP Estático**:
   ```bash
   # Agregar entradas ARP estáticas
   arp -s 192.168.1.1 AA:BB:CC:DD:EE:FF
   ```

2. **Software de Detección**:
   - ArpON
   - Arpwatch
   - XArp

3. **VPN**:
   - Usar VPN para cifrar todo el tráfico

### Prevención de DNS Spoofing

1. **DNSSEC**:
   - Implementar validación DNSSEC

2. **DNS sobre HTTPS (DoH)**:
   - Usar DNS cifrado

3. **Verificar Certificados**:
   - Siempre verificar certificados SSL/TLS

## 🐛 Solución de Problemas

### La aplicación no detecta hosts

**Problema**: No aparecen hosts al escanear
**Solución**:
```bash
# Verificar permisos
sudo whoami  # Debe mostrar "root"

# Verificar interfaz de red
ip link show

# Ejecutar con interfaz específica
sudo python3 network_spoofer_pro.py
```

### Error de permisos

**Problema**: "Permission denied"
**Solución**:
```bash
# Dar permisos al script
chmod +x network_spoofer_pro.py

# Ejecutar con sudo
sudo python3 network_spoofer_pro.py
```

### ARP Spoofing no funciona

**Problema**: Los hosts no reciben paquetes envenenados
**Solución**:
```bash
# Habilitar IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1

# Verificar que esté habilitado
cat /proc/sys/net/ipv4/ip_forward  # Debe mostrar "1"
```

### Scapy no funciona

**Problema**: Errores con Scapy
**Solución**:
```bash
# Reinstalar Scapy
sudo pip3 uninstall scapy
sudo pip3 install scapy

# Verificar instalación
python3 -c "from scapy.all import *; print('OK')"
```

## 📚 Referencias y Recursos

### Documentación Técnica
- [Scapy Documentation](https://scapy.readthedocs.io/)
- [ARP Protocol - RFC 826](https://tools.ietf.org/html/rfc826)
- [DNS Protocol - RFC 1035](https://tools.ietf.org/html/rfc1035)

### Seguridad de Redes
- OWASP Testing Guide
- NIST Cybersecurity Framework
- CEH (Certified Ethical Hacker) Materials

### Libros Recomendados
- "The Web Application Hacker's Handbook"
- "Network Security Assessment"
- "Metasploit: The Penetration Tester's Guide"

## 🤝 Contribución

Este proyecto es con fines educativos. Si deseas contribuir:

1. Reporta bugs y vulnerabilidades
2. Sugiere mejoras de funcionalidad
3. Mejora la documentación
4. Comparte casos de uso educativos

## ⚖️ Consideraciones Legales

### Uso Autorizado Únicamente

Esta herramienta debe usarse SOLO en las siguientes circunstancias:

✅ **Permitido**:
- Tu propia red doméstica
- Laboratorios de prueba aislados
- Entornos virtuales (VMs)
- Con autorización por escrito del propietario de la red
- Fines educativos en instituciones autorizadas

❌ **Prohibido**:
- Redes públicas (cafeterías, hoteles, etc.)
- Redes corporativas sin autorización
- Redes de terceros sin permiso
- Cualquier uso malicioso

### Responsabilidad del Usuario

El desarrollador de esta herramienta:
- **NO** se hace responsable del uso indebido
- **NO** apoya actividades ilegales
- **NO** proporciona soporte para usos no autorizados

El usuario asume toda la responsabilidad legal de sus acciones.

## 📜 Licencia

Este software se proporciona "tal cual" con fines educativos únicamente.

**Uso Educativo Solamente**

Copyright © 2025 - Todos los derechos reservados

## 🔗 Contacto y Soporte

Para reportar problemas o sugerencias:
- Abre un issue en el repositorio
- Proporciona logs detallados
- Incluye información del sistema

---

**Recuerda**: Con gran poder viene gran responsabilidad. Usa esta herramienta de manera ética y legal. 🔒

---

*Desarrollado con Python 🐍 | Scapy 📦 | Tkinter 🖥️*
