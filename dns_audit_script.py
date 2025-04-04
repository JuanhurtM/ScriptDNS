#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DNS Auditing Tool
----------------
Herramienta educativa para la auditoría de servidores DNS.
Desarrollada para el curso de Ciberseguridad.

Autor: Juan Jose Hurtado Mejia
Fecha: 5 Abril 2024
"""

import argparse
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Set, Tuple, Union

import dns.message
import dns.name
import dns.query
import dns.resolver
import requests
import shodan

# Constantes git config user.email "jjuanjose1019@gmail.com"
DEFAULT_TIMEOUT = 5  # Tiempo de espera para consultas DNS (segundos)
DEFAULT_DOMAINS = ["google.com", "facebook.com", "amazon.com", "microsoft.com", "apple.com"]
DEFAULT_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT"]
SHODAN_RESULTS_PER_PAGE = 100
AMPLIFICATION_THRESHOLD = 10  # Umbral para considerar amplificación (ratio respuesta/consulta)
DNS_PORT = 53
BLACKLIST_URL = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"

class DNSAuditTool:
    """Clase principal para la herramienta de auditoría DNS."""

    def __init__(self, api_key: str, verbose: bool = False, output_file: Optional[str] = None):
        """
        Inicializa la herramienta con la clave API de Shodan.
        
        Args:
            api_key: Clave API de Shodan
            verbose: Modo detallado para mostrar más información
            output_file: Archivo para guardar resultados
        """
        self.api_key = api_key
        self.verbose = verbose
        self.output_file = output_file
        self.api = shodan.Shodan(api_key)
        self.results = {
            "dns_servers": [],
            "statistics": {
                "total_servers": 0,
                "responsive_servers": 0,
                "recursive_servers": 0,
                "vulnerable_to_amplification": 0,
                "blacklisted_servers": 0
            }
        }
        self.blacklist = set()
        
        if output_file:
            # Crear el directorio si no existe
            os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
    
    def load_blacklist(self) -> None:
        """Carga la lista negra de IPs maliciosas desde una fuente externa."""
        try:
            self.print_info("Cargando lista negra de IPs...")
            response = requests.get(BLACKLIST_URL, timeout=DEFAULT_TIMEOUT)
            if response.status_code == 200:
                # Filtrar líneas de comentarios y espacios en blanco
                self.blacklist = set(
                    line.strip() for line in response.text.split('\n')
                    if line and not line.startswith('#')
                )
                self.print_success(f"Lista negra cargada: {len(self.blacklist)} IPs")
            else:
                self.print_error(f"Error al cargar lista negra. Código: {response.status_code}")
        except Exception as e:
            self.print_error(f"Error al cargar lista negra: {str(e)}")
            
    def search_dns_servers(self, limit: int = 100, offset: int = 0) -> List[Dict]:
        """
        Busca servidores DNS expuestos en Shodan.
        
        Args:
            limit: Número máximo de resultados a devolver
            offset: Desplazamiento para la paginación
            
        Returns:
            Lista de servidores DNS encontrados
        """
        dns_servers = []
        try:
            # Consulta por DNS (puerto 53)
            query = f"port:{DNS_PORT}"
            
            # Iniciar búsqueda
            self.print_info(f"Buscando servidores DNS expuestos: {query}")
            
            # Calcular el número de páginas necesarias
            num_pages = (limit + SHODAN_RESULTS_PER_PAGE - 1) // SHODAN_RESULTS_PER_PAGE
            
            # Realizar la consulta paginada
            for page in range(1, num_pages + 1):
                if self.verbose:
                    self.print_info(f"Obteniendo página {page} de {num_pages}...")
                
                try:
                    # Calcular el número de resultados a solicitar en esta página
                    page_size = min(SHODAN_RESULTS_PER_PAGE, limit - len(dns_servers))
                    
                    # Consultar Shodan
                    results = self.api.search(query, page=page)
                    
                    # Procesar resultados
                    for result in results['matches']:
                        if len(dns_servers) >= limit:
                            break
                            
                        server_info = {
                            'ip': result['ip_str'],
                            'port': result.get('port', DNS_PORT),
                            'country': result.get('location', {}).get('country_name', 'Unknown'),
                            'isp': result.get('isp', 'Unknown'),
                            'hostnames': result.get('hostnames', []),
                            'last_update': result.get('timestamp', ''),
                            'is_blacklisted': result['ip_str'] in self.blacklist
                        }
                        
                        dns_servers.append(server_info)
                        
                    # Si no hay más resultados, salir del bucle
                    if len(results['matches']) < SHODAN_RESULTS_PER_PAGE:
                        break
                        
                except shodan.APIError as e:
                    self.print_error(f"Error en la página {page}: {str(e)}")
                    if "No information available" in str(e):
                        break
                
                # Pausa para evitar superar límites de API
                time.sleep(1)
                
            self.print_success(f"Se encontraron {len(dns_servers)} servidores DNS")
            
        except shodan.APIError as e:
            self.print_error(f"Error de API Shodan: {str(e)}")
            
        self.results["statistics"]["total_servers"] = len(dns_servers)
        self.results["statistics"]["blacklisted_servers"] = sum(1 for server in dns_servers if server.get('is_blacklisted'))
        return dns_servers
        
    def verify_dns_resolution(self, ip: str, domains: List[str] = DEFAULT_DOMAINS) -> Dict:
        """
        Verifica si un servidor DNS puede resolver dominios correctamente.
        
        Args:
            ip: Dirección IP del servidor DNS a verificar
            domains: Lista de dominios a consultar
            
        Returns:
            Diccionario con resultados de la verificación
        """
        results = {
            "ip": ip,
            "responsive": False,
            "resolved_domains": {},
            "resolution_rate": 0.0
        }
        
        # Configurar resolver personalizado
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [ip]
        resolver.timeout = DEFAULT_TIMEOUT
        resolver.lifetime = DEFAULT_TIMEOUT
        
        domains_resolved = 0
        
        for domain in domains:
            try:
                answers = resolver.resolve(domain, 'A')
                results["resolved_domains"][domain] = [answer.address for answer in answers]
                domains_resolved += 1
                if self.verbose:
                    self.print_info(f"Servidor {ip} resolvió {domain} → {', '.join(results['resolved_domains'][domain])}")
            except Exception as e:
                results["resolved_domains"][domain] = f"Error: {str(e)}"
                if self.verbose:
                    self.print_error(f"Error al resolver {domain} con {ip}: {str(e)}")
        
        # Calcular tasa de resolución
        results["resolution_rate"] = domains_resolved / len(domains) if domains else 0
        results["responsive"] = domains_resolved > 0
        
        return results

    def check_recursivity(self, ip: str) -> Dict:
        """
        Verifica si un servidor DNS permite consultas recursivas.
        
        Args:
            ip: Dirección IP del servidor DNS a verificar
            
        Returns:
            Diccionario con resultados de la verificación
        """
        result = {
            "ip": ip,
            "is_recursive": False,
            "details": ""
        }
        
        try:
            # Crear una consulta DNS con recursión deseada
            query = dns.message.make_query(
                'example.com',
                dns.rdatatype.A,
                rdclass=dns.rdataclass.IN
            )
            
            # Configurar la bandera RD (Recursion Desired)
            query.flags |= dns.flags.RD
            
            # Enviar la consulta y recibir la respuesta
            response = dns.query.udp(query, ip, timeout=DEFAULT_TIMEOUT)
            
            # Verificar si el servidor respondió y si la bandera RA (Recursion Available) está establecida
            if response and response.flags & dns.flags.RA:
                result["is_recursive"] = True
                result["details"] = "El servidor responde a consultas recursivas"
            else:
                result["details"] = "El servidor no permite recursión"
            
        except Exception as e:
            result["details"] = f"Error al verificar recursividad: {str(e)}"
            
        return result

    def check_amplification(self, ip: str) -> Dict:
        """
        Detecta si un servidor DNS es vulnerable a ataques de amplificación.
        
        Args:
            ip: Dirección IP del servidor DNS a verificar
            
        Returns:
            Diccionario con resultados de la verificación
        """
        result = {
            "ip": ip,
            "is_vulnerable": False,
            "amplification_factor": 0,
            "details": ""
        }
        
        try:
            # Consulta pequeña (ANY para cualquier registro de un dominio)
            query = dns.message.make_query(
                'example.com',
                dns.rdatatype.ANY,
                rdclass=dns.rdataclass.IN
            )
            
            # Enviar la consulta y medir el tamaño
            query_size = len(query.to_wire())
            
            # Enviar la consulta y recibir la respuesta
            response = dns.query.udp(query, ip, timeout=DEFAULT_TIMEOUT)
            
            # Si hay respuesta, calcular el factor de amplificación
            if response:
                response_size = len(response.to_wire())
                amplification_factor = response_size / query_size
                
                result["amplification_factor"] = round(amplification_factor, 2)
                
                if amplification_factor > AMPLIFICATION_THRESHOLD:
                    result["is_vulnerable"] = True
                    result["details"] = f"Servidor vulnerable a amplificación DNS. Factor: {amplification_factor:.2f}x"
                else:
                    result["details"] = f"Servidor no vulnerable a amplificación. Factor: {amplification_factor:.2f}x"
            else:
                result["details"] = "Sin respuesta del servidor"
                
        except Exception as e:
            result["details"] = f"Error al verificar amplificación: {str(e)}"
            
        return result
        
    def analyze_dns_server(self, server: Dict, domains: List[str] = DEFAULT_DOMAINS) -> Dict:
        """
        Analiza un servidor DNS realizando todas las verificaciones.
        
        Args:
            server: Información del servidor DNS
            domains: Lista de dominios a consultar
            
        Returns:
            Diccionario con resultados del análisis
        """
        ip = server['ip']
        self.print_info(f"Analizando servidor DNS: {ip}")
        
        # Realizar todas las verificaciones
        resolution_results = self.verify_dns_resolution(ip, domains)
        
        # Solo verificar recursividad y amplificación si el servidor responde
        if resolution_results["responsive"]:
            recursivity_results = self.check_recursivity(ip)
            amplification_results = self.check_amplification(ip)
        else:
            recursivity_results = {"ip": ip, "is_recursive": False, "details": "Servidor no responde"}
            amplification_results = {"ip": ip, "is_vulnerable": False, "amplification_factor": 0, "details": "Servidor no responde"}
        
        # Crear resultado completo
        result = {
            **server,
            "resolution": resolution_results,
            "recursivity": recursivity_results,
            "amplification": amplification_results,
        }
        
        # Actualizar estadísticas
        if resolution_results["responsive"]:
            self.results["statistics"]["responsive_servers"] += 1
        if recursivity_results["is_recursive"]:
            self.results["statistics"]["recursive_servers"] += 1
        if amplification_results["is_vulnerable"]:
            self.results["statistics"]["vulnerable_to_amplification"] += 1
            
        return result
    
    def run(self, max_servers: int = 10, domains: List[str] = DEFAULT_DOMAINS, 
            concurrent: int = 5) -> Dict:
        """
        Ejecuta el análisis completo de servidores DNS.
        
        Args:
            max_servers: Número máximo de servidores a analizar
            domains: Lista de dominios a consultar
            concurrent: Número de análisis concurrentes
            
        Returns:
            Resultados completos del análisis
        """
        start_time = time.time()
        self.print_info("Iniciando auditoría DNS...")
        
        # Cargar lista negra
        self.load_blacklist()
        
        # Buscar servidores DNS
        dns_servers = self.search_dns_servers(limit=max_servers)
        
        if not dns_servers:
            self.print_error("No se encontraron servidores DNS para analizar")
            return self.results
            
        self.print_info(f"Analizando {len(dns_servers)} servidores DNS...")
        
        # Analizar servidores (procesamiento en paralelo)
        with ThreadPoolExecutor(max_workers=concurrent) as executor:
            # Mapear la función de análisis a cada servidor
            future_to_server = {
                executor.submit(self.analyze_dns_server, server, domains): server
                for server in dns_servers
            }
            
            # Recolectar resultados a medida que se completen
            for future in future_to_server:
                try:
                    result = future.result()
                    self.results["dns_servers"].append(result)
                except Exception as e:
                    server = future_to_server[future]
                    self.print_error(f"Error al analizar {server['ip']}: {str(e)}")
        
        # Guardar resultados si se especificó un archivo
        if self.output_file:
            self.save_results()
            
        # Mostrar estadísticas
        elapsed_time = time.time() - start_time
        self.print_success(f"Auditoría completada en {elapsed_time:.2f} segundos")
        self.print_statistics()
        
        return self.results
    
    def save_results(self) -> None:
        """Guarda los resultados en un archivo JSON."""
        try:
            with open(self.output_file, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2)
            self.print_success(f"Resultados guardados en {self.output_file}")
        except Exception as e:
            self.print_error(f"Error al guardar resultados: {str(e)}")
    
    def print_statistics(self) -> None:
        """Muestra estadísticas del análisis."""
        stats = self.results["statistics"]
        print("\n" + "="*60)
        print(f"ESTADÍSTICAS DE AUDITORÍA DNS")
        print("="*60)
        print(f"Total de servidores analizados: {stats['total_servers']}")
        print(f"Servidores que responden: {stats['responsive_servers']} ({self.percentage(stats['responsive_servers'], stats['total_servers'])}%)")
        print(f"Servidores recursivos: {stats['recursive_servers']} ({self.percentage(stats['recursive_servers'], stats['total_servers'])}%)")
        print(f"Servidores vulnerables a amplificación: {stats['vulnerable_to_amplification']} ({self.percentage(stats['vulnerable_to_amplification'], stats['total_servers'])}%)")
        print(f"Servidores en lista negra: {stats['blacklisted_servers']} ({self.percentage(stats['blacklisted_servers'], stats['total_servers'])}%)")
        print("="*60)
    
    def percentage(self, part: int, total: int) -> float:
        """Calcula un porcentaje con formato."""
        return round((part / total) * 100 if total else 0, 1)
    
    def print_info(self, message: str) -> None:
        """Imprime un mensaje informativo."""
        print(f"[*] {message}")
        
    def print_success(self, message: str) -> None:
        """Imprime un mensaje de éxito."""
        print(f"[+] {message}")
        
    def print_error(self, message: str) -> None:
        """Imprime un mensaje de error."""
        print(f"[-] {message}")
        
    def print_verbose(self, message: str) -> None:
        """Imprime un mensaje en modo detallado."""
        if self.verbose:
            print(f"[v] {message}")


def main():
    """Función principal."""
    # Configurar argumentos de línea de comandos
    parser = argparse.ArgumentParser(description='Herramienta de Auditoría DNS para Ciberseguridad')
    parser.add_argument('-k', '--api-key', required=True, help='Clave API de Shodan')
    parser.add_argument('-n', '--num-servers', type=int, default=10, help='Número de servidores a analizar (default: 10)')
    parser.add_argument('-d', '--domains', nargs='+', default=DEFAULT_DOMAINS, help='Dominios a consultar')
    parser.add_argument('-c', '--concurrent', type=int, default=5, help='Número de análisis concurrentes (default: 5)')
    parser.add_argument('-o', '--output', help='Archivo de salida (JSON)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Modo detallado')
    
    args = parser.parse_args()
    
    # Crear instancia de la herramienta
    tool = DNSAuditTool(api_key=args.api_key, verbose=args.verbose, output_file=args.output)
    
    try:
        # Ejecutar la auditoría
        results = tool.run(max_servers=args.num_servers, domains=args.domains, concurrent=args.concurrent)
        
        # Salida exitosa
        return 0
        
    except KeyboardInterrupt:
        print("\n[!] Auditoría interrumpida por el usuario.")
        return 1
        
    except Exception as e:
        print(f"\n[!] Error: {str(e)}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
