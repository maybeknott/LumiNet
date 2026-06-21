import os
import re

to_port_dir = r"D:\GitHub\LumiNet\TO PORT"
output_file = r"D:\GitHub\LumiNet\TO_PORT_DETAILED_ANALYSIS.md"

def scan_projects():
    if not os.path.exists(to_port_dir):
        print(f"Directory {to_port_dir} does not exist.")
        return

    subdirs = [d for d in os.listdir(to_port_dir) if os.path.isdir(os.path.join(to_port_dir, d))]
    subdirs.sort()

    report = []
    report.append("# Detailed Analysis of Projects in TO PORT\n")
    report.append(f"Total projects found: {len(subdirs)}\n")

    for idx, subdir in enumerate(subdirs, 1):
        project_path = os.path.join(to_port_dir, subdir)
        
        # 1. Gather file extensions count
        extensions = {}
        all_files = []
        for root, dirs, files in os.walk(project_path):
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                extensions[ext] = extensions.get(ext, 0) + 1
                all_files.append(os.path.join(root, file))

        # 2. Find and parse README
        readme_content = ""
        readme_file = None
        for file in os.listdir(project_path):
            if file.lower().startswith("readme"):
                readme_file = os.path.join(project_path, file)
                break
        
        if readme_file:
            try:
                with open(readme_file, 'r', encoding='utf-8', errors='ignore') as f:
                    readme_content = f.read(1500) # read first 1500 chars
            except Exception as e:
                readme_content = f"Error reading readme: {str(e)}"
        else:
            # Check one level deep for readme if empty at top
            for file in all_files:
                if os.path.basename(file).lower().startswith("readme"):
                    try:
                        with open(file, 'r', encoding='utf-8', errors='ignore') as f:
                            readme_content = f.read(1000)
                        break
                    except:
                        pass

        # 3. Detect key tech / mechanisms
        keywords = {
            "sni": r"\bsni\b|sni[-_]spoofer|sni[-_]bypass|sni[-_]spoofing",
            "cloudflare": r"cloudflare|cf[-_]scanner|clean[-_]ip|cfray",
            "vpn": r"vpn|wireguard|openvpn|tun2socks|tunfd|anyconnect",
            "socks": r"socks|socks5|socks4",
            "tunnel": r"tunnel|g[-_]tunnel|qq[-_]tunnel|masque|xhttp",
            "proxy": r"proxy|shadowsocks|vmess|vless|trojan|xray|v2ray|obfs",
            "evasion": r"evasion|decoy|active[-_]probing|fallback|obfuscation|obfuscate|nipo",
            "captcha": r"captcha|solvecaptcha|recaptcha|hcaptcha|funcaptcha"
        }
        
        detected_mechanisms = []
        readme_lower = readme_content.lower()
        for mech, regex in keywords.items():
            # Check readme content or files path or directory name
            if re.search(regex, readme_lower) or re.search(regex, subdir.lower()):
                detected_mechanisms.append(mech)
            else:
                # check if any file paths match
                for fpath in all_files[:200]:
                    if re.search(regex, os.path.basename(fpath).lower()):
                        detected_mechanisms.append(mech)
                        break

        detected_mechanisms = list(set(detected_mechanisms))

        # 4. Find key code files
        key_files = []
        for file in all_files:
            bname = os.path.basename(file).lower()
            if bname in ["main.go", "lib.rs", "main.rs", "main.py", "server.js", "app.js", "index.js", "package.json", "go.mod", "cargo.toml", "main.tsx"]:
                key_files.append(os.path.relpath(file, project_path))
            elif bname.endswith(".go") or bname.endswith(".rs") or bname.endswith(".py") or bname.endswith(".cpp"):
                if len(key_files) < 8 and not any(x in file for x in ["node_modules", "vendor", "target"]):
                    key_files.append(os.path.relpath(file, project_path))

        # Build Markdown entry
        report.append(f"## {idx}. {subdir}")
        report.append(f"**Path**: `TO PORT/{subdir}`")
        report.append(f"**Detected Mechanisms**: {', '.join(detected_mechanisms) if detected_mechanisms else 'None'}")
        report.append(f"**Languages/Extensions**: {', '.join([f'{k} ({v})' for k, v in extensions.items() if v > 0][:8])}")
        
        if key_files:
            report.append("**Key Source Files**:")
            for kf in key_files[:10]:
                to_port_dir_fixed = to_port_dir.replace('\\', '/')
                kf_fixed = kf.replace('\\', '/')
                report.append(f"- [{kf}](file:///{to_port_dir_fixed}/{subdir}/{kf_fixed})")
        
        report.append("\n**Description/Readme Extract**:")
        if readme_content:
            # clean up raw text a bit
            readme_clean = readme_content.strip()
            # replace backticks or blockquotes to avoid breaking formatting
            report.append("```markdown")
            report.append(readme_clean[:1200] + ("..." if len(readme_clean) > 1200 else ""))
            report.append("```")
        else:
            report.append("*No Readme / Description available.*")
            
        report.append("\n" + "-" * 40 + "\n")

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("\n".join(report))

    print(f"Scanned {len(subdirs)} projects and wrote report to {output_file}")

if __name__ == "__main__":
    scan_projects()
