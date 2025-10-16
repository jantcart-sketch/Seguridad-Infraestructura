# 🔓 SOLUCIÓN COMPLETA - Spot the Risk

## 🎯 Las 15 Vulnerabilidades Identificadas

---

## 🔴 VULNERABILIDADES CRÍTICAS (5 puntos cada una)

### 1. Firewall Completamente Abierto (0.0.0.0/0 - Todos los puertos)

**Problema:**
El firewall permite TODO el tráfico desde cualquier origen a cualquier puerto.

**Impacto:**
- Exposición total de todos los servicios internos
- Atacantes pueden escanear y acceder a cualquier servicio
- Anula completamente la seguridad perimetral

**Solución:**
```yaml
# Firewall restrictivo
Reglas:
  - Permitir: 80/tcp (HTTP) desde 0.0.0.0/0
  - Permitir: 443/tcp (HTTPS) desde 0.0.0.0/0
  - Permitir: 22/tcp (SSH) solo desde IPs corporativas
  - Denegar: Todo lo demás por defecto
```

**Principio violado:** Defensa en profundidad, Mínimo privilegio

---

### 2. Secretos Hardcodeados en el Código

**Problema:**
Las aplicaciones tienen credenciales y secretos directamente en el código fuente.

**Impacto:**
- Exposición de credenciales en repositorios Git
- Imposible rotar secretos sin redesplegar
- Acceso a bases de datos y servicios si el código se filtra

**Solución:**
```python
# ❌ MAL
DB_PASSWORD = "admin123"
API_KEY = "sk-1234567890"

# ✅ BIEN
import os
DB_PASSWORD = os.getenv('DB_PASSWORD')
API_KEY = os.getenv('API_KEY')

# O mejor aún: usar un gestor de secretos
from vault import get_secret
DB_PASSWORD = get_secret('database/password')
```

**Herramientas:**
- HashiCorp Vault
- AWS Secrets Manager
- Azure Key Vault
- Docker Secrets

**Principio violado:** Confidencialidad

---

### 3. Base de Datos PostgreSQL Expuesta Públicamente

**Problema:**
Puerto 5432 accesible desde Internet con credenciales débiles.

**Impacto:**
- Acceso directo a todos los datos sensibles
- Posible exfiltración masiva de datos
- Modificación o eliminación de datos
- Cumplimiento regulatorio (GDPR, PCI-DSS)

**Solución:**
```yaml
# Configuración de red segura
Database:
  network: private  # Solo red interna
  firewall:
    - allow: 10.0.2.0/24  # Solo desde red de aplicación
    - deny: all
  
  # Credenciales fuertes
  user: db_app_user
  password: [generada aleatoriamente, 32+ caracteres]
  
  # Cifrado
  ssl: required
  ssl_mode: verify-full
```

**Principio violado:** Confidencialidad, Defensa en profundidad

---

### 4. Redis Sin Autenticación y Expuesto

**Problema:**
Redis accesible sin contraseña desde cualquier lugar.

**Impacto:**
- Lectura/escritura de datos en caché
- Posible ejecución de comandos (CONFIG, EVAL)
- Escalada de privilegios mediante módulos maliciosos
- Denegación de servicio (FLUSHALL)

**Solución:**
```conf
# redis.conf
requirepass [contraseña-fuerte-aleatoria]
bind 127.0.0.1  # Solo localhost
protected-mode yes
rename-command FLUSHDB ""
rename-command FLUSHALL ""
rename-command CONFIG ""
```

**Ataque real:** Muchos ransomware explotan Redis sin autenticación

**Principio violado:** Confidencialidad, Integridad, Disponibilidad

---

### 5. Credenciales por Defecto en Admin Panel (admin/admin)

**Problema:**
phpMyAdmin accesible con usuario y contraseña por defecto.

**Impacto:**
- Acceso administrativo completo a la base de datos
- Ejecución de SQL arbitrario
- Posible shell reverso mediante SQL injection
- Descarga de toda la base de datos

**Solución:**
```yaml
# Mejores prácticas para paneles de administración
Admin Panel:
  # 1. Cambiar credenciales inmediatamente
  user: [usuario-único]
  password: [contraseña-fuerte-32+chars]
  
  # 2. Restringir acceso por IP
  firewall:
    - allow: 10.0.0.0/8  # Solo red corporativa
    - allow: VPN_IP_RANGE
  
  # 3. Autenticación de dos factores
  mfa: enabled
  
  # 4. Mejor aún: no exponerlo
  access: bastion-host-only
```

**Principio violado:** Confidencialidad, Integridad

---

## 🟠 VULNERABILIDADES ALTAS (3 puntos cada una)

### 6. Tráfico HTTP Sin Cifrar (Puerto 80)

**Problema:**
Load balancer solo acepta HTTP, no HTTPS.

**Impacto:**
- Credenciales transmitidas en texto plano
- Datos sensibles interceptables (Man-in-the-Middle)
- Sesiones secuestrables (session hijacking)
- No cumple estándares de seguridad (PCI-DSS)

**Solución:**
```nginx
# Configuración del Load Balancer
server {
    listen 80;
    return 301 https://$host$request_uri;  # Redirigir a HTTPS
}

server {
    listen 443 ssl http2;
    
    ssl_certificate /etc/ssl/certs/cert.pem;
    ssl_certificate_key /etc/ssl/private/key.pem;
    
    # Configuración SSL moderna
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    
    # HSTS
    add_header Strict-Transport-Security "max-age=31536000" always;
}
```

**Principio violado:** Confidencialidad

---

### 7. Todos los Servicios Ejecutándose como Root

**Problema:**
Nginx, Python Flask y otros servicios corren con usuario root.

**Impacto:**
- Si un servicio es comprometido, el atacante tiene acceso root
- Puede modificar cualquier archivo del sistema
- Puede instalar backdoors persistentes
- Escalada de privilegios trivial

**Solución:**
```dockerfile
# Dockerfile seguro
FROM python:3.11-slim

# Crear usuario no-privilegiado
RUN useradd -m -u 1000 appuser

# Instalar dependencias como root
COPY requirements.txt .
RUN pip install -r requirements.txt

# Cambiar ownership
COPY --chown=appuser:appuser . /app
WORKDIR /app

# Cambiar a usuario no-privilegiado
USER appuser

CMD ["python", "app.py"]
```

```yaml
# docker-compose.yml
services:
  web:
    user: "1000:1000"  # UID:GID no-root
```

**Principio violado:** Mínimo privilegio

---

### 8. PostgreSQL Versión Desactualizada (9.6)

**Problema:**
PostgreSQL 9.6 tiene múltiples CVEs conocidos y está fuera de soporte.

**Impacto:**
- Vulnerabilidades conocidas explotables
- Sin parches de seguridad
- Posible ejecución remota de código
- Escalada de privilegios

**CVEs conocidos en PostgreSQL 9.6:**
- CVE-2019-10130: Bypass de autenticación
- CVE-2020-25695: Ejecución de código arbitrario
- CVE-2021-32027: Buffer overflow

**Solución:**
```yaml
# Actualizar a versión soportada
database:
  image: postgres:16-alpine  # Versión actual y soportada
  
  # Proceso de actualización
  # 1. Backup completo
  # 2. Probar en staging
  # 3. Actualización con pg_upgrade
  # 4. Verificar funcionamiento
```

**Principio violado:** Disponibilidad, Integridad

---

### 9. SSH con Autenticación por Password Expuesto a Internet

**Problema:**
Puerto 22 abierto a Internet con autenticación por contraseña.

**Impacto:**
- Ataques de fuerza bruta
- Credential stuffing
- Acceso no autorizado al servidor
- Instalación de malware/ransomware

**Solución:**
```bash
# /etc/ssh/sshd_config
PasswordAuthentication no
PubkeyAuthentication yes
PermitRootLogin no
Port 2222  # Cambiar puerto por defecto (seguridad por oscuridad adicional)

# Restringir por IP
AllowUsers admin@10.0.0.0/8
```

```yaml
# Firewall
SSH:
  - allow: 22/tcp from VPN_IP only
  - deny: 22/tcp from 0.0.0.0/0
```

**Mejores prácticas:**
- Usar claves SSH (4096 bits)
- Implementar fail2ban
- Usar bastion host
- Considerar VPN para acceso administrativo

**Principio violado:** Confidencialidad, Defensa en profundidad

---

### 10. Backups Sin Cifrar en Directorio Temporal

**Problema:**
Backups almacenados en /tmp sin cifrado.

**Impacto:**
- Datos sensibles accesibles en texto plano
- /tmp puede ser accesible por otros procesos
- Backups pueden ser eliminados automáticamente
- Violación de cumplimiento regulatorio

**Solución:**
```bash
# Script de backup seguro
#!/bin/bash

# Variables
BACKUP_DIR="/var/backups/encrypted"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
GPG_KEY="backup@company.com"

# Crear backup
pg_dump database > /tmp/backup_${TIMESTAMP}.sql

# Cifrar con GPG
gpg --encrypt \
    --recipient ${GPG_KEY} \
    --output ${BACKUP_DIR}/backup_${TIMESTAMP}.sql.gpg \
    /tmp/backup_${TIMESTAMP}.sql

# Eliminar backup sin cifrar
shred -u /tmp/backup_${TIMESTAMP}.sql

# Permisos restrictivos
chmod 600 ${BACKUP_DIR}/backup_${TIMESTAMP}.sql.gpg

# Transferir a almacenamiento remoto
aws s3 cp ${BACKUP_DIR}/backup_${TIMESTAMP}.sql.gpg \
    s3://backups-bucket/ \
    --storage-class GLACIER
```

**Principio violado:** Confidencialidad

---

## 🟡 VULNERABILIDADES MEDIAS (2 puntos cada una)

### 11. Logs Deshabilitados en Todos los Servicios

**Problema:**
No hay registro de eventos en ningún componente.

**Impacto:**
- Imposible detectar intrusiones
- No hay evidencia forense en caso de incidente
- Incumplimiento de auditorías
- No se pueden identificar patrones anómalos

**Solución:**
```yaml
# Configuración de logging centralizado
logging:
  driver: "json-file"
  options:
    max-size: "10m"
    max-file: "3"
    labels: "service,environment"

# Enviar a sistema centralizado
filebeat:
  inputs:
    - type: container
      paths:
        - '/var/lib/docker/containers/*/*.log'
  output:
    elasticsearch:
      hosts: ["elasticsearch:9200"]
```

**Qué registrar:**
- Intentos de autenticación (exitosos y fallidos)
- Accesos a datos sensibles
- Cambios de configuración
- Errores y excepciones
- Tráfico de red anómalo

**Herramientas:**
- ELK Stack (Elasticsearch, Logstash, Kibana)
- Splunk
- Graylog
- CloudWatch Logs

**Principio violado:** Detección y respuesta

---

### 12. Sin Segmentación de Red Interna

**Problema:**
Todos los servicios backend en la misma red sin firewall interno.

**Impacto:**
- Movimiento lateral fácil para atacantes
- Un servicio comprometido = todos comprometidos
- No hay aislamiento entre componentes

**Solución:**
```yaml
# Segmentación de red con Docker
networks:
  frontend:
    driver: bridge
    ipam:
      config:
        - subnet: 10.0.1.0/24
  
  backend:
    driver: bridge
    internal: true  # Sin acceso a Internet
    ipam:
      config:
        - subnet: 10.0.2.0/24
  
  database:
    driver: bridge
    internal: true
    ipam:
      config:
        - subnet: 10.0.3.0/24

services:
  web:
    networks:
      - frontend
      - backend
  
  app:
    networks:
      - backend
      - database
  
  db:
    networks:
      - database  # Solo accesible desde app
```

**Principio violado:** Defensa en profundidad

---

### 13. Sin Límites de Recursos en Contenedores

**Problema:**
No hay límites de CPU/memoria configurados.

**Impacto:**
- Denegación de servicio por consumo excesivo
- Un contenedor puede agotar recursos del host
- Imposible predecir comportamiento bajo carga

**Solución:**
```yaml
services:
  web:
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 512M
        reservations:
          cpus: '0.25'
          memory: 256M
    
    # Límites adicionales
    ulimits:
      nofile:
        soft: 1024
        hard: 2048
    
    # Prevenir fork bombs
    pids_limit: 100
```

**Principio violado:** Disponibilidad

---

### 14. Admin Panel (phpMyAdmin) Accesible Públicamente

**Problema:**
Panel de administración expuesto a Internet.

**Impacto:**
- Superficie de ataque innecesaria
- Target para ataques automatizados
- Posible explotación de vulnerabilidades de phpMyAdmin

**Solución:**
```yaml
# Opción 1: Restringir por IP
admin_panel:
  networks:
    - internal
  labels:
    - "traefik.http.middlewares.admin-ipwhitelist.ipwhitelist.sourcerange=10.0.0.0/8"

# Opción 2: Acceso solo via bastion host
# No exponer el puerto públicamente

# Opción 3: VPN obligatoria
# Requiere conexión VPN para acceder
```

**Mejor práctica:** Usar herramientas CLI en lugar de interfaces web para administración.

**Principio violado:** Mínimo privilegio, Defensa en profundidad

---

### 15. Sin Sistema de Monitoreo ni Alertas

**Problema:**
No hay monitoreo activo ni sistema de alertas.

**Impacto:**
- Incidentes no detectados en tiempo real
- Degradación de servicio no notificada
- Imposible responder rápidamente a ataques

**Solución:**
```yaml
# Stack de monitoreo
monitoring:
  prometheus:
    image: prom/prometheus
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    ports:
      - "9090:9090"
  
  grafana:
    image: grafana/grafana
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=secure_password
  
  alertmanager:
    image: prom/alertmanager
    volumes:
      - ./alertmanager.yml:/etc/alertmanager/alertmanager.yml
```

```yaml
# alertmanager.yml - Ejemplo de alertas
route:
  receiver: 'team-notifications'
  
receivers:
  - name: 'team-notifications'
    slack_configs:
      - api_url: 'https://hooks.slack.com/services/XXX'
        channel: '#security-alerts'
    
    pagerduty_configs:
      - service_key: 'XXX'
```

**Métricas críticas a monitorear:**
- CPU, memoria, disco
- Tasa de errores HTTP
- Latencia de respuesta
- Intentos de autenticación fallidos
- Tráfico de red anómalo

**Principio violado:** Detección y respuesta

---

## 📊 RESUMEN DE PUNTUACIÓN

| Severidad | Cantidad | Puntos Unitarios | Total |
|-----------|----------|------------------|-------|
| 🔴 Crítico | 5 | 5 | 25 |
| 🟠 Alto | 5 | 3 | 15 |
| 🟡 Medio | 5 | 2 | 10 |
| **TOTAL** | **15** | - | **50** |

---

## 🏗️ ARQUITECTURA SEGURA PROPUESTA

```
                                    INTERNET
                                       │
                                       │
                    ┌──────────────────┴──────────────────┐
                    │                                     │
                    │    FIREWALL: Restrictivo            │
                    │    - 443/tcp (HTTPS) ✅             │
                    │    - 80/tcp → redirect 443 ✅       │
                    │    - Todo lo demás: DENY ✅         │
                    │                                     │
                    └──────────────────┬──────────────────┘
                                       │
                    ┌──────────────────┴──────────────────┐
                    │                                     │
                    │   LOAD BALANCER (HTTPS + TLS 1.3)   │
                    │   + WAF (ModSecurity)                │
                    │   IP: 203.0.113.10                   │
                    │   Puerto: 443 ✅                     │
                    │                                     │
                    └──────────────────┬──────────────────┘
                                       │
                ┏━━━━━━━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━┓
                ┃            RED DMZ (10.0.1.0/24)             ┃
                ┃            Firewall: Solo 443 ✅             ┃
                ┗━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┛
                                       │
        ┌──────────────────────────────┼──────────────────────────────┐
        │                              │                              │
   ┌────▼────┐                    ┌────▼────┐                    ┌────▼────┐
   │  WEB 1  │                    │  WEB 2  │                    │  WEB 3  │
   │ nginx   │                    │ nginx   │                    │ nginx   │
   │ appuser ✅                   │ appuser ✅                   │ appuser ✅
   │ v1.25   ✅                   │ v1.25   ✅                   │ v1.25   ✅
   │ Logs: ON ✅                  │ Logs: ON ✅                  │ Logs: ON ✅
   └────┬────┘                    └────┬────┘                    └────┬────┘
        │                              │                              │
        └─────────┬────────────────────┴──────────────────┬──────────┘
                  │                                        │
                ┏━┻━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┻━┓
                ┃   RED BACKEND (10.0.2.0/24)               ┃
                ┃   Firewall interno ✅                      ┃
                ┃   Sin acceso a Internet ✅                 ┃
                ┗━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━┛
                  │                                        │
             ┌────▼────┐                              ┌────▼────┐
             │  APP 1  │                              │  APP 2  │
             │ Python  │                              │ Python  │
             │ appuser ✅                             │ appuser ✅
             │ Secrets: Vault ✅                      │ Secrets: Vault ✅
             │ Logs: ON ✅                            │ Logs: ON ✅
             └────┬────┘                              └────┬────┘
                  │                                        │
                  └────────────────┬───────────────────────┘
                                   │
                ┏━━━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━┓
                ┃   RED DATABASE (10.0.3.0/24)         ┃
                ┃   Aislada ✅                          ┃
                ┃   Solo acceso desde backend ✅        ┃
                ┗━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┛
                                   │
        ┌──────────────────────────┼──────────────────────────┐
        │                          │                          │
   ┌────▼────┐                ┌────▼────┐              ┌─────▼─────┐
   │DATABASE │                │  REDIS  │              │ ADMIN     │
   │PostgreSQL                │ Cache   │              │ (Bastion) │
   │ v16 ✅  │                │         │              │           │
   │Port:5432│                │Auth: ON ✅              │VPN only ✅│
   │Internal │                │Internal │              │MFA ✅     │
   │SSL: ON ✅                │Logs: ON ✅              │Logs: ON ✅│
   │User: app│                │         │              │           │
   │Pass:Vault✅              │         │              │           │
   │Logs: ON ✅               │         │              │           │
   └─────────┘                └─────────┘              └───────────┘


   ┌─────────────────────────────────────────────────────────┐
   │  BACKUPS (Servidor separado) ✅                          │
   │  - S3 con cifrado ✅                                     │
   │  - Versionado habilitado ✅                              │
   │  - Acceso via IAM roles ✅                               │
   │  - Retención: 30 días ✅                                 │
   │  - Pruebas de restauración mensuales ✅                  │
   └─────────────────────────────────────────────────────────┘


   ┌─────────────────────────────────────────────────────────┐
   │  MONITOREO Y SEGURIDAD ✅                                │
   │  - Prometheus + Grafana ✅                               │
   │  - ELK Stack para logs ✅                                │
   │  - AlertManager configurado ✅                           │
   │  - IDS/IPS (Suricata) ✅                                 │
   │  - Escaneo de vulnerabilidades semanal ✅                │
   └─────────────────────────────────────────────────────────┘
```

---

## 🎯 LECCIONES CLAVE

### 1. Defensa en Profundidad
No confíes en una sola capa de seguridad. Múltiples controles independientes.

### 2. Mínimo Privilegio
Dar solo los permisos necesarios, nada más.

### 3. Cifrado Siempre
Datos en reposo y en tránsito deben estar cifrados.

### 4. Monitoreo Continuo
No puedes proteger lo que no puedes ver.

### 5. Actualización Constante
Software desactualizado = vulnerabilidades conocidas.

### 6. Gestión de Secretos
Nunca en código, siempre en gestores dedicados.

### 7. Segmentación de Red
Limita el movimiento lateral de atacantes.

### 8. Principio de Fallo Seguro
Por defecto: denegar. Permitir explícitamente solo lo necesario.

---

## 📚 RECURSOS ADICIONALES

**Frameworks de seguridad:**
- OWASP Top 10
- CIS Benchmarks
- NIST Cybersecurity Framework

**Herramientas de escaneo:**
- Trivy (contenedores)
- OWASP ZAP (aplicaciones web)
- Nmap (red)
- Lynis (sistema)

**Certificaciones:**
- CompTIA Security+
- Certified Ethical Hacker (CEH)
- CISSP

---

**¡Felicitaciones por completar el ejercicio!** 🎉
**Ahora estás mejor preparado para identificar y mitigar riesgos de seguridad.**
