import gradio as gr
import os
import sys
import io
from main import main as vuln_main  # Certifique-se que sua função main aceita file_path como argumento

def run_vuln_tracker(dep_file):
    file_path = dep_file.name if hasattr(dep_file, "name") else dep_file
    
    # Salva o arquivo enviado
    ext = file_path.split('.')[-1]
    if ext == "txt":
        save_path = "dependencies/requirements.txt"
    elif ext == "json":
        save_path = "dependencies/package.json"
    else:
        return "Arquivo não suportado.", ""
    
    os.makedirs("dependencies", exist_ok=True)

    # Copia o conteúdo
    with open(file_path, "rb") as src, open(save_path, "wb") as dst:
        dst.write(src.read())

    # Redireciona stdout para capturar prints
    old_stdout = sys.stdout
    sys.stdout = mystdout = io.StringIO()

    # Roda o main
    try:
        vuln_main(save_path)
    except Exception as e:
        print(f"Erro: {e}")

    # Restaura stdout
    sys.stdout = old_stdout
    logs = mystdout.getvalue()

    # Lê o relatório final
    report = ""
    if os.path.exists("vulnTrackerReport.md"):
        with open("vulnTrackerReport.md", "r", encoding="utf-8") as f:
            report = f.read()

    return report, logs

iface = gr.Interface(
    fn=run_vuln_tracker,
    inputs=gr.File(label="Arquivo de dependências (.txt ou .json)"),
    outputs=[
        gr.Textbox(label="Relatório final", lines=20),
        gr.Textbox(label="Logs do processo", lines=15),
    ],
    title="Vuln Tracker",
    description="Faça upload do seu arquivo de dependências (requirements.txt ou package.json) e veja o relatório de vulnerabilidades."
)

if __name__ == "__main__":
    iface.launch()