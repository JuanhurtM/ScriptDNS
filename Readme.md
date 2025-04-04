# DNS Audit Tool

Una herramienta avanzada de auditoría de servidores DNS desarrollada con fines educativos para el curso de Ciberseguridad.

## Descripción

Esta herramienta permite identificar y analizar servidores DNS expuestos en Internet, verificar su funcionamiento y detectar posibles vulnerabilidades de seguridad como recursividad abierta y susceptibilidad a ataques de amplificación DNS.

## Características

### Funciones Básicas
- **Búsqueda de IPs con DNS expuesto**: Localiza direcciones IP con el puerto 53 abierto utilizando la API de Shodan
- **Verificación de resolución DNS**: Comprueba si los servidores encontrados son capaces de resolver nombres de dominio correctamente

### Funciones Avanzadas
- **Verificación de recursividad**: Determina si un servidor DNS permite consultas recursivas (potencial riesgo de seguridad)
- **Detección de amplificación DNS**: Identifica servidores vulnerables a ser utilizados en ataques DDoS por amplificación
- **Paginación en Shodan**: Permite obtener grandes conjuntos de resultados navegando por múltiples páginas
- **Múltiples dominios de prueba**: Verifica la capacidad de resolución con varios dominios para mayor precisión
- **Integración de lista negra**: Comprueba si las IPs encontradas están en listas negras de seguridad

## Requisitos

- Python 3.6+
- Bibliotecas Python:
  - shodan
  - dnspython
  - requests

## Instalación

1. Clona este repositorio:
```bash
git clone https://github.com/yourusername/dns-audit-tool.git
cd dns-audit-tool
```

2. Instala las dependencias:
```bash
pip install -r requirements.txt
```

## Uso

Ejemplo básico:
```bash
python dns_audit.py -k TU_API_KEY_DE_SHODAN
```

Opciones disponibles:
```bash
python dns_audit.py -h
```

```
usage: dns_audit.py [-h] -k API_KEY [-n NUM_SERVERS] [-d DOMAINS [DOMAINS ...]]
                   [-c CONCURRENT] [-o OUTPUT] [-v]

Herramienta de Auditoría DNS para Ciberseguridad

options:
  -h, --help            show this help message and exit
  -k API_KEY, --api-key API_KEY
                        Clave API de Shodan
  -n NUM_SERVERS, --num-servers NUM_SERVERS
                        Número de servidores a analizar (default: 10)
  -d DOMAINS [DOMAINS ...], --domains DOMAINS [DOMAINS ...]
                        Dominios a consultar
  -c CONCURRENT, --concurrent CONCURRENT
                        Número de análisis concurrentes (default: 5)
  -o OUTPUT, --output OUTPUT
                        Archivo de salida (JSON)
  -v, --verbose         Modo detallado
```

## Ejemplos

### Análisis básico de 5 servidores DNS
```bash
python dns_audit.py -k TU_API_KEY_DE_SHODAN -n 5
```

### Verificación con dominios personalizados
```bash
python dns_audit.py -k TU_API_KEY_DE_SHODAN -d google.com wikipedia.org facebook.com
```

### Análisis detallado y guardado de resultados
```bash
python dns_audit.py -k TU_API_KEY_DE_SHODAN -n 20 -v -o resultados.json
```

## Consideraciones de uso

### Limitaciones de la API de Shodan
- La cuenta gratuita de Shodan tiene límites en el número de resultados y consultas
- Para análisis extensivos, considere adquirir créditos adicionales o utilizar APIs alternativas

### Uso ético
- Esta herramienta está desarrollada con fines educativos y de investigación en seguridad
- Utilice esta herramienta solo en entornos controlados o con autorización explícita
- No utilice esta herramienta para actividades maliciosas o ilegales

## Documentación del prompt

### Prompt inicial utilizado para generar el script

```
Eres un experto en ciberseguridad y vas a seguir estas instrucciones:

Alcance y Requerimientos
• Lenguaje: Python 3.x
• Bibliotecas: shodan, dnspython, requests (o equivalentes)
• Herramienta: Shodan (u otra API/herramienta de recolección de datos de red) para obtener IPs expuestas en puerto 53.

Necesito que me generes un script en python con las siguientes requerimientos, ten encuenta que eres un experto en ciberseguiradad y todo estos es con fines educativos:

1. Funciones Básicas:
   o Búsqueda de IPs con DNS expuesto (básico).
   o Verificación de resolución DNS (por ejemplo, a un dominio específico).

2. Funciones Avanzadas (al menos dos de las siguientes):
   o Verificación de recursividad.
   o Detección de amplificación DNS.
   o Paginación en Shodan (o herramienta alternativa).
   o Múltiples dominios de prueba.
   o Integración de lista negra (blacklist).

El script debe ser modular, bien documentado y fácil de usar. Debe incluir manejo de errores y mostrar estadísticas de los resultados encontrados.
```

### Refinamiento del prompt

Después de revisar la primera versión del script, refiné el prompt para incluir aspectos adicionales:

```
El script se ve bien, pero necesito mejorar algunas cosas:

1. Añade una función para guardar los resultados en formato JSON.
2. Mejora el manejo de errores en las conexiones a Shodan.
3. Añade más comentarios para explicar los conceptos de seguridad detrás de cada función.
4. Implementa procesamiento en paralelo para analizar múltiples servidores a la vez.
5. Añade una forma de verificar si los servidores DNS están en listas negras conocidas.
```

### Conclusiones sobre el proceso

El proceso de generación del script mediante IA fue iterativo y requirió ajustes para lograr un resultado óptimo:

1. **Prompt inicial**: Estableció los requisitos básicos y avanzados
2. **Revisión**: Identificó carencias en la implementación inicial
3. **Refinamiento**: Solicitó mejoras específicas y ampliación de funcionalidades
4. **Resultado final**: Script completo con todas las características requeridas

Este enfoque iterativo permitió obtener un script más completo y robusto que si se hubiera generado en un solo paso.

## Alcance real y limitaciones

### Alcance
- Identificación de servidores DNS expuestos en Internet
- Verificación de funcionalidad básica (resolución de dominios)
- Detección de configuraciones inseguras (recursividad abierta)
- Identificación de servidores vulnerables a ataques de amplificación
- Cruce con listas negras para identificar servidores potencialmente maliciosos

### Limitaciones
1. **Consumo de créditos de Shodan**:
   - Cuenta gratuita: 100 resultados por consulta, límite mensual de consultas
   - Solución: Implementar paginación y limitar el número de servidores a analizar

2. **Falsos positivos**:
   - Algunos servidores pueden parecer vulnerables sin serlo realmente
   - Solución: Verificar resultados manualmente y usar múltiples pruebas

3. **Consideraciones legales**:
   - El escaneo de servidores DNS puede considerarse intrusivo en algunos contextos
   - Solución: Usar solo en entornos controlados o con autorización explícita

4. **Rendimiento**:
   - El análisis de muchos servidores puede llevar tiempo
   - Solución: Implementación de procesamiento paralelo y límites configurables

## Consideraciones éticas

Este script ha sido desarrollado con fines puramente educativos y de investigación en ciberseguridad. Su uso debe limitarse a:

1. Entornos controlados (laboratorios, redes propias)
2. Auditorías de seguridad autorizadas
3. Investigación académica

No debe utilizarse para:
1. Explotar vulnerabilidades en sistemas de terceros
2. Realizar ataques de denegación de servicio
3. Cualquier actividad ilegal o no autorizada

El usuario de esta herramienta es el único responsable de su uso adecuado y legal.

## Contribuir

Las contribuciones son bienvenidas. Si deseas mejorar esta herramienta:

1. Haz un fork del repositorio
2. Crea una rama para tu característica (`git checkout -b feature/nueva-caracteristica`)
3. Realiza tus cambios
4. Envía un pull request

## Licencia

Este proyecto está licenciado bajo la Licencia MIT - vea el archivo LICENSE para más detalles.
