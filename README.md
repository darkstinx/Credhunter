# credhunter

Herramienta de línea de comandos que escanea directorios home de Linux en busca de credenciales expuestas en 7 categorías, clasifica cada hallazgo por severidad en función de los permisos del archivo y el riesgo de exposición, y genera un informe en terminal (con código de colores) o en JSON estructurado para automatización.

Desarrollada para enumeración post-explotación en CTFs (por ejemplo, HackTheBox) y como proyecto de portfolio. **Ejecútala únicamente en sistemas y cuentas sobre los que tengas autorización.**

---

## Categorías

| Categoría               | Ejemplos                                                                                      |
|-------------------------|-----------------------------------------------------------------------------------------------|
| `ssh_keys`              | Claves privadas `~/.ssh/id_*` sin cifrar                                                      |
| `cloud_credentials`     | AWS `~/.aws/credentials`, GCP ADC JSON, tokens Azure CLI, kubeconfig, auth Docker registry, credenciales Terraform |
| `browser_credentials`   | Base de datos SQLite `Login Data` de Chrome/Chromium/Brave/Edge, `logins.json`/`key4.db` de Firefox |
| `shell_history`         | Líneas de `.bash_history`/`.zsh_history`/etc. con `curl -u`, `mysql -p`, `sshpass`, secretos exportados |
| `keyrings`              | Archivos de llavero GNOME, archivos KDE KWallet                                               |
| `git_tokens`            | `.git-credentials`, `.netrc`, `hosts.yml` de GitHub CLI, `.npmrc`, `.pypirc`, `auth.json` de Composer |
| `app_credentials`       | Archivos `.env`, `.pgpass`, `.my.cnf`, `sitemanager.xml` de FileZilla, patrones genéricos `clave=valor` con secretos en archivos de configuración |

---

## Modelo de severidad

Cada hallazgo parte de una severidad base específica por categoría, que puede escalarse según los permisos del archivo:

- Archivo legible por todos → siempre **CRITICAL**
- Archivo legible por el grupo → sube un nivel
- En caso contrario → severidad base (por ejemplo, una clave SSH sin cifrar es HIGH incluso con permisos 600; una clave protegida por passphrase es LOW)

---

## Uso

```bash
# Escanear el home del usuario actual
python3 credhunter.py

# Escanear un directorio específico (por ejemplo, el home de otro usuario al que tenemos acceso)
python3 credhunter.py --path /home/otrousuario

# Escanear todos los directorios home del sistema (necesita root para cobertura completa)
sudo python3 credhunter.py --all-users

# Solo hallazgos de alto impacto, salida JSON a un archivo
python3 credhunter.py --min-severity HIGH --json -o report.json

# Enmascarar valores de secretos en lugar de mostrarlos completos (ideal para capturas de portfolio)
python3 credhunter.py --redact

# Ejecutar solo categorías específicas
python3 credhunter.py --category ssh_keys --category git_tokens
```

### Flags disponibles

| Flag | Descripción |
|------|-------------|
| `--path DIR` | Directorio home a escanear (repetible). Por defecto: home del usuario actual. |
| `--all-users` | Escanea todos los directorios bajo `/home` (y `/root` si se ejecuta como root). |
| `--category` | Ejecuta solo la categoría indicada (repetible). Por defecto: todas. |
| `--min-severity` | Filtra hallazgos por severidad mínima: `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`. |
| `--redact` | Enmascara los valores de secretos en el informe. |
| `--json` | Salida en JSON estructurado en lugar del informe de terminal. |
| `-o, --output FILE` | Escribe el informe en un archivo en lugar de stdout. |
| `--no-color` | Desactiva los colores ANSI en la salida de terminal. |
| `--brief` | Modo terminal: muestra solo el resumen de conteos. |
| `--max-depth N` / `--max-files N` | Ajusta el límite del recorrido recursivo de `app_credentials`. |

---

## Requisitos

Python 3 — solo librería estándar. No necesita `pip install` para ejecutarse en una máquina objetivo.

`colorama` (ver `requirements.txt`) es opcional y solo relevante en consolas Windows antiguas. En Linux la salida con colores funciona sin ninguna dependencia.

---

## Notas

- Los hallazgos de `browser_credentials` para navegadores basados en Chromium detectan si el blob de contraseña almacenado está en texto plano, protegido por el llavero del sistema operativo (`v11`), o protegido por la clave de respaldo fija usada cuando no hay demonio de llavero activo (`v10` — frecuentemente recuperable offline).
- Los archivos mayores de 1 MB se omiten, y el recorrido recursivo de `app_credentials` está limitado (`--max-depth`, `--max-files`) para mantener los escaneos rápidos en directorios home de gran tamaño.
- Los errores de permisos al leer archivos de otros usuarios se contabilizan y se reportan, pero no son fatales.

---

## Tecnologías

| Componente   | Detalle                                      |
|--------------|----------------------------------------------|
| Lenguaje     | Python 3 (solo librería estándar)            |
| Interfaz     | Terminal ANSI con código de colores          |
| Salida       | Terminal coloreado o JSON estructurado       |
| Entorno      | Linux (probado en Kali Linux)                |

---

## Autor

**Ignacio González Domínguez**  
[GitHub](https://github.com/darkstinx) · [LinkedIn](https://www.linkedin.com/in/ignacio-gonzalez-dominguez/) · [Portfolio](https://darkstinx.github.io)
