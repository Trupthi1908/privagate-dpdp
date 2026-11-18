"""PrivaGate Streamlit Application Entrypoint.

Delegates execution to ui.py to support running either:
    streamlit run app.py
or:
    streamlit run ui.py
"""
import runpy
from pathlib import Path

if __name__ == "__main__":
    ui_script = Path(__file__).parent / "ui.py"
    runpy.run_path(str(ui_script), run_name="__main__")
