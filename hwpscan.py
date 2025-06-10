
import olefile

def signature_file(filepath):
    """
    다양한 파일 시그니처를 비교하여 문서 유형을 판별하는 함수
    """
    signature_patterns = {
        b'\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1': "HWP 5.0 이상",
        b'HWP Document File': "HWP 3.x",
        b'\x7FELF': "ELF Executable (Linux)",
        b'\x89PNG\r\n\x1a\n': "PNG 이미지",
        b'\xFF\xD8\xFF': "JPEG 이미지",
        b'PK\x03\x04': "ZIP 또는 DOCX 등 OpenXML 기반 문서",
        b'MZ': "PE 실행 파일 (Windows EXE)",
    }

    try:
        with open(filepath, "rb") as f:
            header = f.read(16)  # 넉넉히 읽어두기
            for sig, description in signature_patterns.items():
                if header.startswith(sig):
                    print(f"파일 헤더: {header}")
                    return f"파일 유형: {description}"
            print(f"파일 헤더: {header}")
            return "알 수 없는 파일 형식입니다."
    except Exception as e:
        return f"파일을 열 수 없습니다: {e}"

# 사용 예시
file_path = "sample1.hwp.hwpx"
result = signature_file(file_path)
print(result)

