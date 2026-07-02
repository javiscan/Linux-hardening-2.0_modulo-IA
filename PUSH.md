# Publicar en GitHub — repo: javiscan/Linux-hardening-2.0_modulo-IA

Ejecutá esto DENTRO de la carpeta `linux-hardening-platform`, en tu equipo
(Linux, o Windows con Git Bash / PowerShell). El repo ya está creado y vacío.

```bash
# 1) Posicionate en la carpeta del proyecto
cd linux-hardening-platform

# 2) Inicializá el repo local (si ya tiene .git de una prueba, borralo antes: rm -rf .git)
git init
git add .
git commit -m "feat: Linux Hardening Platform v2.0 - framework modular, telemetria JSON y modulo EDR"
git branch -M main

# 3) Conectá tu repo remoto y subí
git remote add origin https://github.com/javiscan/Linux-hardening-2.0_modulo-IA.git
git push -u origin main
```

## Autenticación (primera vez)
- **HTTPS (lo más simple):** al hacer `git push` te pedirá usuario y un
  **Personal Access Token** (Settings → Developer settings → Tokens) como contraseña.
- **SSH (alternativa):** si tenés clave SSH cargada en GitHub, usá el remoto:
  `git remote set-url origin git@github.com:javiscan/Linux-hardening-2.0_modulo-IA.git`

## Actualizaciones futuras
```bash
git add .
git commit -m "descripción del cambio"
git push
```

## Recomendado tras el primer push
- Poné una descripción y topics al repo (bash, hardening, security, siem, devsecops).
- Activá el workflow de ShellCheck si copiás `.github/workflows/` del otro toolkit.
- Creá un tag de versión: `git tag v2.0.0 && git push --tags`.
