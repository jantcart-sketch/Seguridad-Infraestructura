# 🚨 DIAGRAMA INSEGURO - Spot the Risk

## 📋 Instrucciones para los Estudiantes

**Objetivo:** Encuentra TODAS las vulnerabilidades de seguridad en este diagrama de infraestructura.

**Tiempo:** 15 minutos en parejas

**Puntuación:**
- 🔴 Crítico: 5 puntos
- 🟠 Alto: 3 puntos
- 🟡 Medio: 2 puntos

---

## 🏗️ ARQUITECTURA DE LA APLICACIÓN "SecureBank Online"

```
                                    INTERNET
                                       │
                                       │
                    ┌──────────────────┴──────────────────┐
                    │                                     │
                    │         FIREWALL: 0.0.0.0/0         │
                    │         (Todos los puertos)         │
                    │                                     │
                    └──────────────────┬──────────────────┘
                                       │
                    ┌──────────────────┴──────────────────┐
                    │                                     │
                    │      LOAD BALANCER (HTTP)           │
                    │      IP: 203.0.113.10               │
                    │      Puerto: 80                     │
                    │                                     │
                    └──────────────────┬──────────────────┘
                                       │
                ┏━━━━━━━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━━━┓
                ┃                                             ┃
                ┃            RED PÚBLICA (DMZ)                ┃
                ┃            10.0.1.0/24                      ┃
                ┃                                             ┃
                ┗━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┛
                                       │
        ┌──────────────────────────────┼──────────────────────────────┐
        │                              │                              │
        │                              │                              │
   ┌────▼────┐                    ┌────▼────┐                    ┌────▼────┐
   │         │                    │         │                    │         │
   │  WEB 1  │                    │  WEB 2  │                    │  WEB 3  │
   │         │                    │         │                    │         │
   │ nginx   │                    │ nginx   │                    │ nginx   │
   │ root    │                    │ root    │                    │ root    │
   │         │                    │         │                    │         │
   └────┬────┘                    └────┬────┘                    └────┬────┘
        │                              │                              │
        │         ┌────────────────────┴──────────────────┐          │
        │         │                                        │          │
        └─────────┼────────────────────────────────────────┼──────────┘
                  │                                        │
                  │                                        │
             ┌────▼────┐                              ┌────▼────┐
             │         │                              │         │
             │  APP 1  │                              │  APP 2  │
             │         │                              │         │
             │ Python  │                              │ Python  │
             │ Flask   │                              │ Flask   │
             │ root    │                              │ root    │
             │         │                              │         │
             │ Secrets:│                              │ Secrets:│
             │ hardcoded                              │ hardcoded
             │ in code │                              │ in code │
             │         │                              │         │
             └────┬────┘                              └────┬────┘
                  │                                        │
                  │                                        │
                  └────────────────┬───────────────────────┘
                                   │
                ┏━━━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━┓
                ┃                                      ┃
                ┃       RED PRIVADA (Backend)          ┃
                ┃       10.0.2.0/24                    ┃
                ┃       (Sin firewall interno)         ┃
                ┃                                      ┃
                ┗━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┛
                                   │
        ┌──────────────────────────┼──────────────────────────┐
        │                          │                          │
        │                          │                          │
   ┌────▼────┐                ┌────▼────┐              ┌─────▼─────┐
   │         │                │         │              │           │
   │DATABASE │                │  REDIS  │              │ ADMIN     │
   │         │                │         │              │ PANEL     │
   │PostgreSQL                │ Cache   │              │           │
   │ v9.6    │                │         │              │ phpMyAdmin│
   │         │                │ No auth │              │           │
   │Port:5432│                │Port:6379│              │Port: 8080 │
   │Public   │                │Public   │              │Public     │
   │         │                │         │              │           │
   │User:    │                │         │              │User/Pass: │
   │postgres │                │         │              │admin/admin│
   │Pass:    │                │         │              │           │
   │admin123 │                │         │              │           │
   │         │                │         │              │           │
   │No SSL   │                │         │              │           │
   │         │                │         │              │           │
   │Logs: OFF│                │Logs: OFF│              │Logs: OFF  │
   │         │                │         │              │           │
   └─────────┘                └─────────┘              └───────────┘


   ┌─────────────────────────────────────────────────────────┐
   │                                                         │
   │  SERVIDOR DE BACKUPS (Mismo servidor)                   │
   │                                                         │
   │  - Backups en /tmp/backups                              │
   │  - Sin cifrado                                          │
   │  - Acceso SSH con password                              │
   │  - Puerto 22 abierto a Internet                         │
   │  - Usuario: backup / Pass: backup123                    │
   │                                                         │
   └─────────────────────────────────────────────────────────┘


   ┌─────────────────────────────────────────────────────────┐
   │                                                         │
   │  MONITOREO Y LOGS                                       │
   │                                                         │
   │  - Logs deshabilitados en la mayoría de servicios      │
   │  - Sin sistema de monitoreo                             │
   │  - Sin alertas configuradas                             │
   │  - Sin IDS/IPS                                          │
   │                                                         │
   └─────────────────────────────────────────────────────────┘
```

---

## 📝 PLANTILLA PARA RESPUESTAS

**Equipo:** _______________

**Integrantes:** _______________ y _______________

---

### Vulnerabilidad #1
- **Componente afectado:** 
- **Descripción del problema:** 
- **Severidad:** ⬜ Crítico  ⬜ Alto  ⬜ Medio
- **Impacto potencial:** 

---

### Vulnerabilidad #2
- **Componente afectado:** 
- **Descripción del problema:** 
- **Severidad:** ⬜ Crítico  ⬜ Alto  ⬜ Medio
- **Impacto potencial:** 

---

### Vulnerabilidad #3
- **Componente afectado:** 
- **Descripción del problema:** 
- **Severidad:** ⬜ Crítico  ⬜ Alto  ⬜ Medio
- **Impacto potencial:** 

---

### Vulnerabilidad #4
- **Componente afectado:** 
- **Descripción del problema:** 
- **Severidad:** ⬜ Crítico  ⬜ Alto  ⬜ Medio
- **Impacto potencial:** 

---

### Vulnerabilidad #5
- **Componente afectado:** 
- **Descripción del problema:** 
- **Severidad:** ⬜ Crítico  ⬜ Alto  ⬜ Medio
- **Impacto potencial:** 

---

### Vulnerabilidad #6
- **Componente afectado:** 
- **Descripción del problema:** 
- **Severidad:** ⬜ Crítico  ⬜ Alto  ⬜ Medio
- **Impacto potencial:** 

---

### Vulnerabilidad #7
- **Componente afectado:** 
- **Descripción del problema:** 
- **Severidad:** ⬜ Crítico  ⬜ Alto  ⬜ Medio
- **Impacto potencial:** 

---

### Vulnerabilidad #8
- **Componente afectado:** 
- **Descripción del problema:** 
- **Severidad:** ⬜ Crítico  ⬜ Alto  ⬜ Medio
- **Impacto potencial:** 

---

### Vulnerabilidad #9
- **Componente afectado:** 
- **Descripción del problema:** 
- **Severidad:** ⬜ Crítico  ⬜ Alto  ⬜ Medio
- **Impacto potencial:** 

---

### Vulnerabilidad #10
- **Componente afectado:** 
- **Descripción del problema:** 
- **Severidad:** ⬜ Crítico  ⬜ Alto  ⬜ Medio
- **Impacto potencial:** 

---

### Vulnerabilidad #11
- **Componente afectado:** 
- **Descripción del problema:** 
- **Severidad:** ⬜ Crítico  ⬜ Alto  ⬜ Medio
- **Impacto potencial:** 

---

### Vulnerabilidad #12
- **Componente afectado:** 
- **Descripción del problema:** 
- **Severidad:** ⬜ Crítico  ⬜ Alto  ⬜ Medio
- **Impacto potencial:** 

---

### Vulnerabilidad #13
- **Componente afectado:** 
- **Descripción del problema:** 
- **Severidad:** ⬜ Crítico  ⬜ Alto  ⬜ Medio
- **Impacto potencial:** 

---

### Vulnerabilidad #14
- **Componente afectado:** 
- **Descripción del problema:** 
- **Severidad:** ⬜ Crítico  ⬜ Alto  ⬜ Medio
- **Impacto potencial:** 

---

### Vulnerabilidad #15
- **Componente afectado:** 
- **Descripción del problema:** 
- **Severidad:** ⬜ Crítico  ⬜ Alto  ⬜ Medio
- **Impacto potencial:** 

---

## 💡 PISTAS (Solo si te quedas atascado)

<details>
<summary>Pista 1: Piensa en los principios básicos</summary>

- ¿Se está aplicando el principio de mínimo privilegio?
- ¿Hay defensa en profundidad?
- ¿Se protege la confidencialidad, integridad y disponibilidad?

</details>

<details>
<summary>Pista 2: Revisa cada capa</summary>

- Perímetro (Firewall)
- Red (Segmentación)
- Aplicación (Configuración)
- Datos (Cifrado, acceso)
- Monitoreo (Logs, alertas)

</details>

<details>
<summary>Pista 3: Busca credenciales</summary>

- ¿Hay contraseñas débiles o por defecto?
- ¿Están los secretos expuestos?
- ¿Hay autenticación en todos los servicios?

</details>

---

## 🎯 OBJETIVO DE APRENDIZAJE

Al completar esta actividad, serás capaz de:

✅ Identificar vulnerabilidades comunes en arquitecturas de infraestructura
✅ Evaluar la severidad de diferentes tipos de riesgos
✅ Aplicar principios de seguridad a casos reales
✅ Proponer soluciones para mitigar riesgos
✅ Pensar como un atacante para defender mejor

---

**¡Buena suerte! 🍀**
**Recuerda: Cada vulnerabilidad que encuentres es un ataque que previenes.**
