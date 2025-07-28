import nvdlib
from openai import OpenAI
import os

def llmInput(info_file):
    intro = "Using the following information about the vulnerabilities of these dependencies," \
        "create a report that explains the problem in an accessible way and makes recommendations to remediate potential threats." \
        "Remember to also mention if a dependency does not appear in the CVE dataset."
    with open(info_file, "r") as f:
        file_content = f.read()
    full_input = intro + "\n" + file_content
    return full_input

def getDepenTxt(file_path):
    names = []
    versions = []
    with open(file_path, 'r') as file:
        for line in file:
            equalPos = line.index('=')
            names.append(line[:equalPos])
            version = line[equalPos+2:].strip()
            versions.append(version)
    return names, versions

def txtOrjson(file_path):
    dotPos = file_path.index('.')
    extension = file_path[dotPos+1:]
    #print(extension)
    return extension

def main():
    #file_path = input("Enter the path to your dependencie file: ")
    file_path = "requirements.txt"
    extension = txtOrjson(file_path)
    #content = getContent(file_path)
    #n_lines = countLines(file_path)
    if extension == 'txt':
        names, versions = getDepenTxt(file_path)
        #print(names,'\n',versions)
    else:
        print('Extension not accepted!')
        return
    
    for i in range(len(names)):
        results = nvdlib.searchCVE(keywordSearch=names[i])
        if results:
            for cve in results:
                with open("info.txt", "a") as f:
                    print(f"{names[i]}", file=f)
                    print(f"CVE ID: {cve.id}", file=f)
                    if cve.descriptions:
                        print(f"Description: {cve.descriptions[0].value}", file=f)
                    if hasattr(cve, 'metrics') and hasattr(cve.metrics, 'cvssMetricV31'):
                        metrics = cve.metrics.cvssMetricV31
                        if metrics and hasattr(metrics[0], 'cvssData'):
                            print(f"Severity: {metrics[0].cvssData.baseSeverity}\n", file=f)
                    else:
                        print("\n", file=f)         

        else:
            with open("info.txt", "a") as f:
                print(f"{names[i]}", file=f)
                print('CVE not found\n', file=f)
    
    openai_key = os.getenv("OPENAI_API_KEY")
    client = OpenAI(api_key=openai_key)
    response = client.responses.create(
        model="gpt-4.1",
        input = llmInput(info_file="info.txt")
    )
    #print(response.output_text)
    with open("vulnTrackerReport.md", "w", encoding="utf-8") as f:
        f.write(response.output_text)


if __name__ == '__main__':
    main()