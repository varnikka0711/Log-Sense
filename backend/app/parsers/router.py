import tempfile
from fastapi import UploadFile

from app.parsers.txt_parser import parse_txt_logs
from app.parsers.evtx_parser import parse_evtx
from app.parsers.xml_parser import parse_xml_logs


def parse_logs(file: UploadFile):
    filename = file.filename.lower()

    # Save uploaded file temporarily
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(file.file.read())
        tmp_path = tmp.name

    # Route to correct parser
    if filename.endswith((".txt", ".log")):
        return parse_txt_logs(tmp_path)

    if filename.endswith(".evtx"):
        return parse_evtx(tmp_path)

    if filename.endswith(".xml"):
        return parse_xml_logs(tmp_path)

    raise ValueError("Unsupported file type")
