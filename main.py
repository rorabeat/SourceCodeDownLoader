import sys
import os
import re
import requests
import zipfile
import tempfile

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QFileDialog,
    QMessageBox, QPlainTextEdit, QProgressBar
)
from PyQt5.QtCore import Qt


def log_append(widget: QPlainTextEdit, text: str):
    """로그 창에 한 줄 추가"""
    widget.appendPlainText(text)
    cursor = widget.textCursor()
    cursor.movePosition(cursor.End)
    widget.setTextCursor(cursor)


def parse_pr_url(url: str):
    """
    예:
      - https://github.com/OWNER/REPO/pull/123
      - https://github.mycompany.com/OWNER/REPO/pull/123
    에서 host, OWNER, REPO, PR번호 추출
    """
    pattern = r"https?://([^/]+)/([^/]+)/([^/]+)/pull/(\d+)"
    m = re.match(pattern, url.strip())
    if not m:
        raise ValueError(
            "PR URL 형식이 잘못되었습니다.\n"
            "예:\n"
            "  https://github.com/OWNER/REPO/pull/123\n"
            "  https://github.mycompany.com/OWNER/REPO/pull/123"
        )

    host, owner, repo, pr_number = m.group(1), m.group(2), m.group(3), m.group(4)
    return host, owner, repo, pr_number


def parse_commit_url(url: str):
    """
    예:
      - https://github.com/OWNER/REPO/commit/SHA
      - https://github.mycompany.com/OWNER/REPO/commit/SHA
    에서 host, OWNER, REPO, 커밋 SHA 추출
    """
    pattern = r"https?://([^/]+)/([^/]+)/([^/]+)/commit/([a-fA-F0-9]+)"
    m = re.match(pattern, url.strip())
    if not m:
        raise ValueError(
            "커밋 URL 형식이 잘못되었습니다.\n"
            "예:\n"
            "  https://github.com/OWNER/REPO/commit/abc123def\n"
            "  https://github.mycompany.com/OWNER/REPO/commit/abc123def"
        )

    host, owner, repo, commit_sha = m.group(1), m.group(2), m.group(3), m.group(4)
    return host, owner, repo, commit_sha


def get_pr_info(host: str, owner: str, repo: str, pr_number: str, token: str = ""):
    """
    GitHub / GitHub Enterprise API로 PR 정보 가져오기
    base(변경 전) / head(변경 후) SHA, repo 정보 추출
    """
    # GitHub.com 과 Enterprise API 엔드포인트 분기
    if host == "github.com":
        api_url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}"
    else:
        # GitHub Enterprise: https://<HOST>/api/v3/...
        api_url = f"https://{host}/api/v3/repos/{owner}/{repo}/pulls/{pr_number}"

    headers = {
        "Accept": "application/vnd.github.v3+json",
    }
    if token:
        headers["Authorization"] = f"token {token}"

    resp = requests.get(api_url, headers=headers)
    if resp.status_code != 200:
        raise RuntimeError(f"GitHub API 요청 실패 (status={resp.status_code})\n{resp.text}")

    data = resp.json()

    base_repo_full = data["base"]["repo"]["full_name"]   # 예: "openai/gpt-4"
    base_sha = data["base"]["sha"]

    head_repo_full = data["head"]["repo"]["full_name"]   # 포크일 수도 있음
    head_sha = data["head"]["sha"]

    return {
        "base_repo_full": base_repo_full,
        "base_sha": base_sha,
        "head_repo_full": head_repo_full,
        "head_sha": head_sha,
        "title": data.get("title", ""),
    }


def get_commit_info(host: str, owner: str, repo: str, commit_sha: str, token: str = ""):
    """
    GitHub / GitHub Enterprise API로 커밋 정보 가져오기
    부모 SHA(변경 전)와 현재 SHA(변경 후) 정보 추출
    """
    # GitHub.com 과 Enterprise API 엔드포인트 분기
    if host == "github.com":
        api_url = f"https://api.github.com/repos/{owner}/{repo}/commits/{commit_sha}"
    else:
        # GitHub Enterprise: https://<HOST>/api/v3/...
        api_url = f"https://{host}/api/v3/repos/{owner}/{repo}/commits/{commit_sha}"

    headers = {
        "Accept": "application/vnd.github.v3+json",
    }
    if token:
        headers["Authorization"] = f"token {token}"

    resp = requests.get(api_url, headers=headers)
    if resp.status_code != 200:
        raise RuntimeError(f"GitHub API 요청 실패 (status={resp.status_code})\n{resp.text}")

    data = resp.json()

    repo_full = f"{owner}/{repo}"
    current_sha = data["sha"]
    
    # 부모 SHA 가져오기 (일반적으로 첫 번째 부모)
    parents = data.get("parents", [])
    if not parents:
        raise RuntimeError("이 커밋은 부모가 없는 최초 커밋입니다. 변경 전 파일을 다운로드할 수 없습니다.")
    
    parent_sha = parents[0]["sha"]

    # 커밋 메시지의 첫 줄을 제목으로 사용
    commit_message = data.get("commit", {}).get("message", "")
    title = commit_message.split("\n")[0].strip() if commit_message else f"commit_{current_sha[:7]}"

    return {
        "base_repo_full": repo_full,
        "base_sha": parent_sha,
        "head_repo_full": repo_full,
        "head_sha": current_sha,
        "title": title,
    }


def get_pr_changed_files(host: str, owner: str, repo: str, pr_number: str, token: str = ""):
    """
    GitHub API를 사용하여 PR에서 실제로 변경된 파일 목록 가져오기
    """
    # GitHub.com 과 Enterprise API 엔드포인트 분기
    if host == "github.com":
        api_url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/files"
    else:
        # GitHub Enterprise: https://<HOST>/api/v3/...
        api_url = f"https://{host}/api/v3/repos/{owner}/{repo}/pulls/{pr_number}/files"

    headers = {
        "Accept": "application/vnd.github.v3+json",
    }
    if token:
        headers["Authorization"] = f"token {token}"

    resp = requests.get(api_url, headers=headers)
    if resp.status_code != 200:
        raise RuntimeError(f"GitHub API 요청 실패 (status={resp.status_code})\n{resp.text}")

    files_data = resp.json()
    
    # 변경된 파일 경로 목록 (추가, 수정, 이름 변경 포함, 삭제 제외)
    changed_filepaths = set()
    for file_data in files_data:
        status = file_data.get("status", "")
        filename = file_data.get("filename", "")
        previous_filename = file_data.get("previous_filename")
        
        # 삭제된 파일은 제외
        if status != "removed":
            changed_filepaths.add(filename)
            # 이름이 변경된 경우 이전 파일명도 포함
            if previous_filename:
                changed_filepaths.add(previous_filename)
    
    return list(changed_filepaths)


def extract_changed_files_from_zip(zip_path: str, changed_filepaths: set, output_dir: str, 
                                   log_widget: QPlainTextEdit = None):
    """
    ZIP 아카이브에서 변경된 파일들만 추출
    """
    extracted_count = 0
    try:
        with zipfile.ZipFile(zip_path, 'r') as zipf:
            # ZIP 내부의 루트 디렉토리 찾기 (보통 REPO-SHA 형식)
            namelist = zipf.namelist()
            if not namelist:
                return extracted_count
            
            # 첫 번째 파일의 경로에서 루트 디렉토리 추출
            root_dir = namelist[0].split('/')[0] + '/'
            
            for filepath in changed_filepaths:
                # ZIP 내부 경로 구성 (REPO-SHA/파일경로)
                zip_internal_path = root_dir + filepath
                
                # 정확한 경로로 시도
                if zip_internal_path in namelist:
                    # 파일 추출
                    extracted_filepath = os.path.join(output_dir, filepath)
                    os.makedirs(os.path.dirname(extracted_filepath), exist_ok=True)
                    
                    with zipf.open(zip_internal_path) as source, open(extracted_filepath, 'wb') as target:
                        target.write(source.read())
                    extracted_count += 1
                else:
                    # 대소문자 무시하여 찾기
                    found = False
                    for zip_path_internal in namelist:
                        # 루트 디렉토리 제거 후 비교
                        relative_path = zip_path_internal[len(root_dir):] if zip_path_internal.startswith(root_dir) else zip_path_internal
                        if relative_path.lower() == filepath.lower() or relative_path.replace('\\', '/') == filepath.replace('\\', '/'):
                            extracted_filepath = os.path.join(output_dir, filepath)
                            os.makedirs(os.path.dirname(extracted_filepath), exist_ok=True)
                            
                            with zipf.open(zip_path_internal) as source, open(extracted_filepath, 'wb') as target:
                                target.write(source.read())
                            extracted_count += 1
                            found = True
                            break
                    
                    if not found and log_widget:
                        log_append(log_widget, f"[!] 파일을 찾을 수 없음: {filepath}")
    except Exception as e:
        if log_widget:
            log_append(log_widget, f"[!] ZIP 추출 오류: {str(e)}")
    
    return extracted_count


def create_filtered_zip_from_archives(base_zip_path: str, head_zip_path: str, 
                                     changed_filepaths: set, output_zip_path: str,
                                     log_widget: QPlainTextEdit, progress_bar: QProgressBar):
    """
    base와 head ZIP에서 변경된 파일들만 추출하여 새로운 ZIP 생성
    """
    temp_dir = tempfile.mkdtemp()
    base_dir = os.path.join(temp_dir, "before")
    head_dir = os.path.join(temp_dir, "after")
    os.makedirs(base_dir, exist_ok=True)
    os.makedirs(head_dir, exist_ok=True)

    try:
        log_append(log_widget, f"[*] base ZIP에서 변경된 파일 {len(changed_filepaths)}개 추출 중...")
        progress_bar.setValue(25)
        QApplication.processEvents()
        extract_changed_files_from_zip(base_zip_path, changed_filepaths, base_dir, log_widget)

        log_append(log_widget, f"[*] head ZIP에서 변경된 파일 {len(changed_filepaths)}개 추출 중...")
        progress_bar.setValue(50)
        QApplication.processEvents()
        extract_changed_files_from_zip(head_zip_path, changed_filepaths, head_dir, log_widget)

        log_append(log_widget, "[*] 필터링된 ZIP 파일 생성 중...")
        progress_bar.setValue(75)
        QApplication.processEvents()

        # 새 ZIP 파일 생성
        with zipfile.ZipFile(output_zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # before 파일들 추가
            for root, dirs, files in os.walk(base_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, base_dir)
                    zipf.write(file_path, f"before/{arcname}")

            # after 파일들 추가
            for root, dirs, files in os.walk(head_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, head_dir)
                    zipf.write(file_path, f"after/{arcname}")

        log_append(log_widget, f"[+] 필터링된 ZIP 파일 생성 완료: {output_zip_path}")

    finally:
        # 임시 디렉토리 정리
        import shutil
        try:
            shutil.rmtree(temp_dir)
        except:
            pass


def download_zip(archive_url: str, out_path: str, token: str,
                 log_widget: QPlainTextEdit, progress_bar: QProgressBar):
    """
    GitHub archive(zip) 다운로드 + 진행률 표시
    """
    headers = {}
    if token:
        headers["Authorization"] = f"token {token}"

    log_append(log_widget, f"[+] 다운로드 시작: {archive_url}")
    resp = requests.get(archive_url, headers=headers, stream=True)
    if resp.status_code != 200:
        raise RuntimeError(f"ZIP 다운로드 실패 (status={resp.status_code})\n{resp.text}")

    total_length = resp.headers.get("Content-Length")
    if total_length is not None:
        total_length = int(total_length)
        progress_bar.setRange(0, 100)   # 0~100%
    else:
        # 길이 모르면 busy 상태
        progress_bar.setRange(0, 0)

    downloaded = 0
    with open(out_path, "wb") as f:
        for chunk in resp.iter_content(chunk_size=8192):
            if chunk:
                f.write(chunk)
                downloaded += len(chunk)

                if total_length:
                    percent = int(downloaded * 100 / total_length)
                    progress_bar.setValue(percent)

                QApplication.processEvents()

    # 끝났으면 100% 고정
    progress_bar.setRange(0, 100)
    progress_bar.setValue(100)

    log_append(log_widget, f"[+] 저장 완료: {out_path} ({downloaded} bytes)")


class PRDownloaderGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        main_layout = QVBoxLayout()

        # PR URL 입력
        url_layout = QVBoxLayout()
        url_label = QLabel("GitHub / 사내 GitHub PR URL 또는 커밋 URL:")
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText(
            "PR: https://github.com/OWNER/REPO/pull/123\n"
            "커밋: https://github.com/OWNER/REPO/commit/abc123def"
        )
        url_layout.addWidget(url_label)
        url_layout.addWidget(self.url_input)
        main_layout.addLayout(url_layout)

        # GitHub 토큰 입력 (선택사항)
        token_layout = QVBoxLayout()
        token_label = QLabel("GitHub Personal Access Token (선택사항):")
        self.token_input = QLineEdit()
        self.token_input.setPlaceholderText("private repo / rate limit 완화를 원하면 입력. public만 쓰면 비워두세요.")
        self.token_input.setEchoMode(QLineEdit.Password)
        token_layout.addWidget(token_label)
        token_layout.addWidget(self.token_input)
        main_layout.addLayout(token_layout)

        # 저장 폴더 선택 (기본 루트 폴더만 지정, 실제 저장은 PR 제목으로 자동 서브폴더 생성)
        out_layout = QHBoxLayout()
        out_label = QLabel("기본 저장 폴더 (선택):")
        self.out_dir_input = QLineEdit()
        self.out_dir_input.setPlaceholderText("비워두면 현재 작업 폴더에 제목 폴더가 생성됩니다.")
        browse_btn = QPushButton("폴더 선택")
        browse_btn.clicked.connect(self.choose_output_dir)

        out_layout.addWidget(out_label)
        out_layout.addWidget(self.out_dir_input)
        out_layout.addWidget(browse_btn)
        main_layout.addLayout(out_layout)

        # 진행률 바
        progress_layout = QVBoxLayout()
        progress_label = QLabel("다운로드 진행률:")
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        progress_layout.addWidget(progress_label)
        progress_layout.addWidget(self.progress_bar)
        main_layout.addLayout(progress_layout)

        # 다운로드 버튼
        self.download_btn = QPushButton("before/after ZIP 다운로드")
        self.download_btn.clicked.connect(self.handle_download)
        main_layout.addWidget(self.download_btn)

        # 로그 창
        log_label = QLabel("로그:")
        self.log_output = QPlainTextEdit()
        self.log_output.setReadOnly(True)
        main_layout.addWidget(log_label)
        main_layout.addWidget(self.log_output)

        self.setLayout(main_layout)
        self.setWindowTitle("GitHub / Enterprise PR/커밋 before/after 소스 ZIP 다운로드")
        self.resize(720, 500)

    def choose_output_dir(self):
        directory = QFileDialog.getExistingDirectory(self, "저장할 기본 폴더 선택")
        if directory:
            self.out_dir_input.setText(directory)

    def handle_download(self):
        pr_url = self.url_input.text().strip()
        token = self.token_input.text().strip()
        out_dir = self.out_dir_input.text().strip()

        self.log_output.clear()
        self.progress_bar.setValue(0)

        if not pr_url:
            QMessageBox.warning(self, "입력 오류", "PR URL 또는 커밋 URL을 입력해주세요.")
            return

        # 기본 출력 폴더 = 현재 실행 위치
        if not out_dir:
            out_dir = os.getcwd()

        if not os.path.isdir(out_dir):
            QMessageBox.warning(self, "경로 오류", "저장 폴더 경로가 존재하지 않습니다.")
            return

        log_append(self.log_output, f"[+] 입력된 URL: {pr_url}")
        log_append(self.log_output, f"[+] 기본 저장 폴더(루트): {out_dir}")

        # PR URL인지 커밋 URL인지 판단
        is_commit_url = "/commit/" in pr_url
        is_pr_url = "/pull/" in pr_url

        if not (is_pr_url or is_commit_url):
            QMessageBox.critical(
                self, "URL 오류",
                "PR URL 또는 커밋 URL을 입력해주세요.\n\n"
                "PR 예: https://github.com/OWNER/REPO/pull/123\n"
                "커밋 예: https://github.com/OWNER/REPO/commit/abc123def"
            )
            log_append(self.log_output, "[에러] 잘못된 URL 형식입니다.")
            return

        try:
            if is_pr_url:
                host, owner, repo, pr_number = parse_pr_url(pr_url)
                log_append(self.log_output, f"[+] PR URL 파싱 결과: host={host}, owner={owner}, repo={repo}, pr={pr_number}")
                info = get_pr_info(host, owner, repo, pr_number, token)
                title = info["title"]
                identifier = f"pr{pr_number}"
            else:  # is_commit_url
                host, owner, repo, commit_sha = parse_commit_url(pr_url)
                log_append(self.log_output, f"[+] 커밋 URL 파싱 결과: host={host}, owner={owner}, repo={repo}, commit={commit_sha[:7]}")
                info = get_commit_info(host, owner, repo, commit_sha, token)
                title = info["title"]
                identifier = f"commit_{commit_sha[:7]}"
        except Exception as e:
            QMessageBox.critical(self, "URL 오류", str(e))
            log_append(self.log_output, f"[에러] {e}")
            return

        base_repo_full = info["base_repo_full"]
        base_sha = info["base_sha"]
        head_repo_full = info["head_repo_full"]
        head_sha = info["head_sha"]

        log_append(self.log_output, f"[+] 제목: {title}")
        log_append(self.log_output, f"[+] base (변경 전): {base_repo_full} @ {base_sha}")
        log_append(self.log_output, f"[+] head (변경 후): {head_repo_full} @ {head_sha}")

        # -----------------------------------------
        # 🔥 자동 폴더 생성: 제목 기반
        # 윈도우에서 폴더명에 쓸 수 없는 문자 제거
        safe_title = re.sub(r'[\\/*?:"<>|]', '_', title).strip() or identifier
        auto_folder = os.path.join(out_dir, safe_title)
        os.makedirs(auto_folder, exist_ok=True)

        log_append(self.log_output, f"[+] 자동 생성된 저장 폴더: {auto_folder}")
        # -----------------------------------------

        # ZIP URL 구성 (GitHub.com / Enterprise 모두 host 사용)
        base_archive_url = f"https://{host}/{base_repo_full}/archive/{base_sha}.zip"
        head_archive_url = f"https://{host}/{head_repo_full}/archive/{head_sha}.zip"

        base_short = base_sha[:7]
        head_short = head_sha[:7]
        base_filename = f"{base_repo_full.replace('/', '_')}_{identifier}_before_{base_short}.zip"
        head_filename = f"{base_repo_full.replace('/', '_')}_{identifier}_after_{head_short}.zip"

        # 🔥 ZIP 저장 위치 = 자동 생성 폴더
        base_out_path = os.path.join(auto_folder, base_filename)
        head_out_path = os.path.join(auto_folder, head_filename)

        try:
            self.download_btn.setEnabled(False)
            QApplication.setOverrideCursor(Qt.WaitCursor)

            if is_pr_url:
                # PR인 경우: 변경된 파일만 필터링하여 다운로드
                log_append(self.log_output, "[*] PR에서 변경된 파일 목록 조회 중...")
                changed_filepaths = set(get_pr_changed_files(host, owner, repo, pr_number, token))
                log_append(self.log_output, f"[+] 변경된 파일 {len(changed_filepaths)}개 발견")

                # 임시로 전체 ZIP 다운로드
                temp_base_zip = os.path.join(tempfile.gettempdir(), f"temp_base_{base_sha[:7]}.zip")
                temp_head_zip = os.path.join(tempfile.gettempdir(), f"temp_head_{head_sha[:7]}.zip")

                try:
                    # before 다운로드
                    self.progress_bar.setValue(0)
                    log_append(self.log_output, "[*] base ZIP 다운로드 중...")
                    download_zip(base_archive_url, temp_base_zip, token, self.log_output, self.progress_bar)

                    # after 다운로드
                    self.progress_bar.setValue(0)
                    log_append(self.log_output, "[*] head ZIP 다운로드 중...")
                    download_zip(head_archive_url, temp_head_zip, token, self.log_output, self.progress_bar)

                    # 필터링된 ZIP 생성
                    filtered_zip_path = os.path.join(auto_folder, f"{base_repo_full.replace('/', '_')}_{identifier}_changed_files.zip")
                    create_filtered_zip_from_archives(
                        temp_base_zip, temp_head_zip, changed_filepaths, 
                        filtered_zip_path, self.log_output, self.progress_bar
                    )

                    # 원본 전체 ZIP도 저장
                    base_out_path = os.path.join(auto_folder, base_filename)
                    head_out_path = os.path.join(auto_folder, head_filename)
                    
                    import shutil
                    shutil.copy2(temp_base_zip, base_out_path)
                    shutil.copy2(temp_head_zip, head_out_path)

                    final_base_path = base_out_path
                    final_head_path = head_out_path
                    final_filtered_path = filtered_zip_path

                finally:
                    # 임시 파일 정리 (이미 이동했으면 존재하지 않음)
                    import shutil
                    for temp_file in [temp_base_zip, temp_head_zip]:
                        if os.path.exists(temp_file):
                            try:
                                os.remove(temp_file)
                            except:
                                pass

            else:
                # 커밋인 경우: 기존 방식 (전체 ZIP 다운로드)
                # before 다운로드
                self.progress_bar.setValue(0)
                log_append(self.log_output, "[*] 변경 전(before) ZIP 다운로드 중...")
                download_zip(base_archive_url, base_out_path, token, self.log_output, self.progress_bar)

                # after 다운로드
                self.progress_bar.setValue(0)
                log_append(self.log_output, "[*] 변경 후(after) ZIP 다운로드 중...")
                download_zip(head_archive_url, head_out_path, token, self.log_output, self.progress_bar)

                final_base_path = base_out_path
                final_head_path = head_out_path
                final_filtered_path = None

        except Exception as e:
            QMessageBox.critical(self, "다운로드 오류", str(e))
            log_append(self.log_output, f"[에러] {e}")
            return
        finally:
            self.download_btn.setEnabled(True)
            QApplication.restoreOverrideCursor()
            self.progress_bar.setValue(100)

        if is_pr_url:
            msg = (
                "다운로드 완료!\n\n"
                f"- 저장 폴더: {auto_folder}\n"
                f"- 변경된 파일만 포함: {final_filtered_path}\n"
                f"- 전체 base ZIP: {final_base_path}\n"
                f"- 전체 head ZIP: {final_head_path}"
            )
        else:
            msg = (
                "다운로드 완료!\n\n"
                f"- 저장 폴더: {auto_folder}\n"
                f"- 변경 전(before): {final_base_path}\n"
                f"- 변경 후(after): {final_head_path}"
            )
        QMessageBox.information(self, "완료", msg)
        log_append(self.log_output, "\n✅ 모든 작업 완료")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PRDownloaderGUI()
    window.show()
    sys.exit(app.exec_())
