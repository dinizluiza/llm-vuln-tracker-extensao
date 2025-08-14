import nvdlib
from dotenv import load_dotenv
from openai import OpenAI
import os
import json

load_dotenv()

CACHE_FILE = "cache.json"
REQUIREMENTS_FILE = "requirementsTest.txt"

def load_cache():
    """Carrega o cache de resultados já obtidos."""
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

def save_cache(cache):
    """Salva o cache atualizado no disco."""
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=4, ensure_ascii=False)

def llmInput(info_file):
    intro = "Using the following information about the vulnerabilities of these dependencies," \
        "create a report that explains the problem in an accessible way and makes recommendations to remediate potential threats" \
        "considering the context of the project." \
        "Remember to also mention if a dependency does not appear in the CVE dataset."
    with open(REQUIREMENTS_FILE, "r", encoding="utf-8") as f:
        dependencies = f.read()
    with open(info_file, "r", encoding="utf-8") as f:
        vuln_info = f.read()
    with open("README.md", "r", errors="ignore") as f:
        project_des = f.read()
    
    full_input = (
        intro + "\n" +
        "Here are the dependencies to be analysed:\n" +
        dependencies + "\n\n" +
        "Here's the information about the vulnerabilities of the dependencies searched on the APIs:\n" +
        vuln_info + "\n\n" +
        "And here's the project description:\n" +
        project_des +
        "For each dependency, provide:\n" \
        "1. a brief summary of the vulnerabilities found\n" \
        "2. the impact of the vulnerabilities in this project\n" \
        "3. recommendations for remediation (that can be upgrades, patches or alternative libraries suggestions)."
    )
    return full_input

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

def txtOrjson(file_path):
    dotPos = file_path.index('.')
    extension = file_path[dotPos+1:]
    return extension

def main():
    file_path = REQUIREMENTS_FILE
    extension = txtOrjson(file_path)

    # Limpa info.txt no início
    open("info.txt", "w", encoding="utf-8").close()

    if extension == 'txt':
        names, versions = getDepenTxt(file_path)
    else:
        print('Extension not accepted!')
        return

    # Carregar cache
    cache = load_cache()

    for name in names:
        if name in cache:
            print(f"[CACHE] {name} already on cache, reusing result.")
            with open("info.txt", "a", encoding="utf-8") as f:
                f.write(cache[name] + "\n")
            continue

        print(f"[NVD] Searching for vulnerabilities in {name}...")
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

        # Salvar no arquivo info.txt
        with open("info.txt", "a", encoding="utf-8") as f:
            f.write(output_str)

        # Guardar no cache
        cache[name] = output_str

    # Salvar cache atualizado
    save_cache(cache)

    # Gerar relatório com LLM
    openai_key = os.getenv("OPENAI_API_KEY")
    client = OpenAI(api_key=openai_key)
    print("[LLM] Generating report with LLM...")
    response = client.responses.create(
        model="gpt-4.1-nano",
        input=llmInput(info_file="info.txt")
    )

    with open("vulnTrackerReport.md", "w", encoding="utf-8") as f:
        f.write(response.output_text)

    print("Execution finished.")

if __name__ == '__main__':
    main()
