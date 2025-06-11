# anaconda / python3 

# pip install olefile
# pip install zlib

import olefile
import os
import zlib
import zipfile
import io

def auto_decompress(data):
    """
    데이터의 압축 포맷을 자동 감지하고 압축 해제 시도.
    성공 시: (1, 압축 해제된 데이터)
    실패 시: (0, 원본 데이터)
    """
    # 압축 포맷 감지
    if data.startswith(b'\x1f\x8b'):
        wbits = 31  # gzip
    elif data.startswith((b'\x78\x01', b'\x78\x9c', b'\x78\xda')):
        wbits = 15  # zlib
    else:
        wbits = -15  # raw deflate

    try:
        decompressed = zlib.decompress(data, wbits=wbits)
        return 1, decompressed # 성공하면, 암호화 해제된 데이터 리턴
    except zlib.error:
        return 0, data #원본 데이터 리턴

def analyze_ole_file(file_path):
    """
    주어진 OLE 파일을 분석하고 항목 목록 및 각 항목의 크기를 출력합니다.
    """
    section_number=0
    if not olefile.isOleFile(file_path):
        print("❌ 이 파일은 OLE 형식이 아닙니다.")
        return

    try:
        ole = olefile.OleFileIO(file_path)
        entries = ole.listdir()

        print(f"\n📂 '{file_path}'의 OLE 항목 목록:")
        for entry in entries:
            entry_path = "/".join(entry)
            section_number+=1
            try:
                with ole.openstream(entry) as stream:
                    data = stream.read()
                    size = len(data)
                    print(f" - {entry_path} ({size} 바이트)")
                    return_flag, return_content = auto_decompress(data)

                    ##################### 여기가 중요함 #################################
                    save_flag = 0
                    if b"VBA" in return_content:
                        save_flag=1
                        print(f"   🔍 'VBA' 발견! ")
                        save_flag = 0
                    if b"DDE" in return_content:
                        save_flag=1
                        print(f"   🔍 'DDE' 발견! ")
                    if b"xor" in return_content:
                        save_flag=1
                        print(f"   🔍 'xor' 발견! ")
                    if b"\x4d\x5a\x00\x00" in return_content:
                        save_flag=1
                        print(f"   🔍 'MZ' 발견! ")
                    if b"\x70\x00\x6f\x00\x77\x00\x65\x00" in return_content:
                        save_flag=1
                        print(f"   🔍 'powershell' 발견 !")
                    if b"90909090" in return_content:
                        save_flag=1
                        print(f"   🔍 'Nop Code' 발견 !")
                    if b"\x53\x00\x61\x00\x76\x00\x65\x00\x54\x00" in return_content:
                        save_flag=1
                        print(f"   🔍 'Script[SaveToFile]' 발견 !")
                    if b"getenv" in return_content:
                        save_flag=1
                        print(f"   🔍 GhostScript 'getenv' 발견 !")
                    if b"Startup" in return_content:
                        save_flag=1
                        print(f"   🔍 GhostScript 'Startup' 발견 !")
                    if b"exec" in return_content:
                        save_flag=1
                        print(f"   🔍 GhostScript 'exec' 발견 !")
                    if b"dup" in return_content:
                        save_flag=1
                        print(f"   🔍 GhostScript 'dup' 발견 !")
                    if b"SQBmACg" in return_content:
                        save_flag=1
                        print(f"   🔍 PowerShell Base64 Code 'SQBmACg' 발견 !")
                    #### 항목에 적용되는 경우만 저장함
                    if(return_flag == True ):
                        print("----> Compressed")
                    if(save_flag == 1) :
                        ## 여기서 압축해제 코드를 저장함
                        print("----> '"+file_path+"' 파일저장")
                        filename = file_path+"_"+str(section_number)+"_decompress.txt"
                        savefile = open(filename,"wb")
                        savefile.write(return_content)
                        savefile.close()
                    ##################### 여기가 중요함 #################################
                     
            except Exception as e:
                print(f" - {entry_path} (⚠️ 크기를 읽을 수 없음: {e})")

        ole.close()

    except Exception as e:
        print(f"❗ OLE 파일 분석 중 오류 발생: {e}")

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

def traverse_and_act(root_dir):
    filecount = 0
    for dirpath, dirnames, filenames in os.walk(root_dir):
        for filename in filenames:
            file_path = os.path.join(dirpath, filename)
            if filename.lower().endswith('.txt'):
                continue
            filecount+=1
            print(filecount, file_path)
            analyze_ole_file(file_path)
            print()

if __name__ == "__main__":
    target_directory = "c:\\dummy_ms"  # 여기에 대상 디렉토리 경로를 입력하세요
    traverse_and_act(target_directory)
