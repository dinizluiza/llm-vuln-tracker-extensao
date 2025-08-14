import nvdlib
from dotenv import load_dotenv
#from openai import OpenAI
import os
import json
import requests

load_dotenv()

CACHE_FILE = "cache/txt/cache.json"
INFO_FILE = "cache/txt/info.txt"

CACHE_FILE_NODE = "cache/json/cache_node.json"
INFO_FILE_NODE = "cache/json/info_node.txt"

def extension_type(file_path):
    dotPos = file_path.index('.')
    extension = file_path[dotPos+1:]
    return extension

def files_type(extension):
    if extension == 'txt':
        return CACHE_FILE, INFO_FILE
    elif extension == 'json':
        return CACHE_FILE_NODE, INFO_FILE_NODE
    else:
        print('Extension not accepted!')
        return

def getDepenTxt(file_path):
    names = []
    versions = []
    with open(file_path, 'r') as file:
        for line in file:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '==' in line:
                name, version = line.split('==', 1)
                names.append(name.strip())
                versions.append(version.strip())
            else:
                names.append(line)
                versions.append("N/A")
    return names, versions

def getDepenJson(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        data = json.load(file)
    names = []
    versions = []
    for dep_type in ["dependencies", "devDependencies"]:
        deps = data.get(dep_type, {})
        for name, version in deps.items():
            names.append(name)
            versions.append(version)
    return names, versions

def load_cache(cache_file):
    """Carrega o cache de resultados já obtidos."""
    if os.path.exists(cache_file):
        with open(cache_file, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

def save_cache(cache, cache_file):
    """Salva o cache atualizado no disco."""
    with open(cache_file, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=4, ensure_ascii=False)

def search_nvd(name):
    results = nvdlib.searchCVE(keywordSearch=name)
    output_str = f"{name}\n"
    if results:
        for cve in results:
            output_str += f"CVE ID: {cve.id}\n"
            if cve.descriptions:
                output_str += f"Description: {cve.descriptions[0].value}\n"
            if hasattr(cve, 'metrics') and hasattr(cve.metrics, 'cvssMetricV31'):
                metrics = cve.metrics.cvssMetricV31
                if metrics and hasattr(metrics[0], 'cvssData'):
                    output_str += f"Severity: {metrics[0].cvssData.baseSeverity}\n"
            output_str += "\n"
    else:
        output_str += "CVE not found\n\n"
    return output_str

def search_osv(name, version):
    url = "https://api.osv.dev/v1/query"
    payload = {
        "package": {
            "name": name,
            "ecosystem": "npm"
        }
    }
    if version and version != "N/A":
        payload["version"] = version
    try:
        resp = requests.post(url, json=payload, timeout=10)
        output_str = f"{name}\n"
        if resp.status_code == 200:
            data = resp.json()
            vulns = data.get("vulns", [])
            if vulns:
                for vuln in vulns:
                    output_str += f"OSV ID: {vuln.get('id')}\n"
                    output_str += f"Summary: {vuln.get('summary','')}\n"
                    output_str += f"Details: {vuln.get('details','')}\n\n"
            else:
                output_str += "No vulnerabilities found (OSV)\n\n"
        else:
            output_str += "Error querying OSV API\n\n"
        return output_str
    except Exception as e:
        return f"{name}\nError querying OSV API: {e}\n\n"
    
def llmInput(info_file, file_path, max_lines=50, max_chars=3000):
    intro = (
        "Using the following summarized information about the vulnerabilities of these dependencies, "
        "create a report that explains the problem in an accessible way and makes recommendations to remediate potential threats "
        "considering the context of the project. "
        "Mention if a dependency does not appear in the vulnerability dataset."
    )

    def summarize(path, max_lines, max_chars):
        try:
            with open(path, "r", encoding="utf-8") as f:
                lines = f.readlines()
                if len(lines) > max_lines:
                    lines = lines[:max_lines]
                    lines.append("\n...[truncated]...\n")
                content = "".join(lines)
                if len(content) > max_chars:
                    content = content[:max_chars] + "\n...[truncated]...\n"
                return content
        except Exception:
            return "[Could not read file]"

    dependencies = summarize(file_path, max_lines, max_chars)
    vuln_info = summarize(info_file, max_lines * 2, max_chars * 2)
    project_des = summarize("README.md", max_lines, max_chars)

    full_input = (
        intro + "\n"
        "Here are the dependencies to be analysed (summarized):\n"
        + dependencies + "\n\n"
        "Here's the summarized information about the vulnerabilities of the dependencies:\n"
        + vuln_info + "\n\n"
        "And here's the (summarized) project description:\n"
        + project_des + "\n"
        "For each dependency, provide:\n"
        "1. a brief summary of the vulnerabilities found\n"
        "2. the impact of the vulnerabilities in this project\n"
        "3. recommendations for remediation (that can be upgrades, patches or alternative libraries suggestions)."
    )
    return full_input

# def llmInput(info_file, file_path):
#     intro = "Using the following information about the vulnerabilities of these dependencies," \
#         "create a report that explains the problem in an accessible way and makes recommendations to remediate potential threats" \
#         "considering the context of the project." \
#         "Remember to also mention if a dependency does not appear in the vulnerability dataset."
#     with open(file_path, "r", encoding="utf-8") as f:
#         dependencies = f.read()
#     with open(info_file, "r", encoding="utf-8") as f:
#         vuln_info = f.read()
#     with open("README.md", "r", errors="ignore") as f:
#         project_des = f.read()
    
#     full_input = (
#         intro + "\n" +
#         "Here are the dependencies to be analysed:\n" +
#         dependencies + "\n\n" +
#         "Here's the information about the vulnerabilities of the dependencies searched on the APIs:\n" +
#         vuln_info + "\n\n" +
#         "And here's the project description:\n" +
#         project_des +
#         "For each dependency, provide:\n" \
#         "1. a brief summary of the vulnerabilities found\n" \
#         "2. the impact of the vulnerabilities in this project\n" \
#         "3. recommendations for remediation (that can be upgrades, patches or alternative libraries suggestions)."
#     )
#     return full_input

def main():
    file_path = "dependencies/package.json"

    extension = extension_type(file_path)
    cache_file, info_file = files_type(extension)

    # Limpa info.txt no início
    open(info_file, "w", encoding="utf-8").close()

    if extension == 'txt':
        names, versions = getDepenTxt(file_path)
    elif extension == 'json':
        names, versions = getDepenJson(file_path)
    else:
        print('Extension not accepted!')
        return

    # Carregar cache
    cache = load_cache(cache_file)

    for name, version in zip(names, versions):
        cache_key = f"{name}@{version}"
        if cache_key in cache:
            print(f"[CACHE] {name} already on cache, reusing result.")
            with open(info_file, "a", encoding="utf-8") as f:
                f.write(cache[cache_key] + "\n")
            continue

        if extension == 'txt':
            print(f"[NVD] Searching for vulnerabilities in {name}...")
            output_str = search_nvd(name)
        elif extension == 'json':
            print(f"[OSV] Searching for vulnerabilities in {name}...")
            output_str = search_osv(name, version)
        else:
            output_str = f"{name}\nUnknown project type\n\n"

        # Salvar no arquivo info.txt
        with open(info_file, "a", encoding="utf-8") as f:
            f.write(output_str)

        # Guardar no cache
        cache[cache_key] = output_str

    # Salvar cache atualizado
    save_cache(cache, cache_file)

    # # Gerar relatório com LLM
    # openai_key = os.getenv("OPENAI_API_KEY")
    # client = OpenAI(api_key=openai_key)
    # print("[LLM] Generating report with LLM...")
    # response = client.responses.create(
    #     model="gpt-4.1",
    #     input=llmInput(info_file, file_path)
    # )

    # with open("vulnTrackerReport.md", "w", encoding="utf-8") as f:
    #     f.write(response.output_text)

    import openai
    openrouter_key = os.getenv("OPENROUTER_API_KEY")
    if not openrouter_key:
        print("OPENROUTER_API_KEY não encontrado no ambiente.")
        return

    openai.api_key = openrouter_key
    openai.api_base = "https://openrouter.ai/api/v1"

    print("[LLM] Generating report with OpenRouter.ai...")

    response = openai.ChatCompletion.create(
        model="tngtech/deepseek-r1t2-chimera:free",  # ou outro modelo disponível no OpenRouter
        messages=[
            {"role": "user", "content": llmInput(info_file, file_path)}
        ]
    )

    with open("vulnTrackerReport.md", "w", encoding="utf-8") as f:
        f.write(response['choices'][0]['message']['content'])

    print("Execution finished.")

if __name__ == '__main__':
    main()