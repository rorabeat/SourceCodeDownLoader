import sys
import os
import re
import requests

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
        head_filename = f"{head_repo_full.replace('/', '_')}_{identifier}_after_{head_short}.zip"

        # 🔥 ZIP 저장 위치 = 자동 생성 폴더
        base_out_path = os.path.join(auto_folder, base_filename)
        head_out_path = os.path.join(auto_folder, head_filename)

        try:
            self.download_btn.setEnabled(False)
            QApplication.setOverrideCursor(Qt.WaitCursor)

            # before 다운로드
            self.progress_bar.setValue(0)
            log_append(self.log_output, "[*] 변경 전(before) ZIP 다운로드 중...")
            download_zip(base_archive_url, base_out_path, token, self.log_output, self.progress_bar)

            # after 다운로드
            self.progress_bar.setValue(0)
            log_append(self.log_output, "[*] 변경 후(after) ZIP 다운로드 중...")
            download_zip(head_archive_url, head_out_path, token, self.log_output, self.progress_bar)

        except Exception as e:
            QMessageBox.critical(self, "다운로드 오류", str(e))
            log_append(self.log_output, f"[에러] {e}")
            return
        finally:
            self.download_btn.setEnabled(True)
            QApplication.restoreOverrideCursor()
            self.progress_bar.setValue(100)

        msg = (
            "다운로드 완료!\n\n"
            f"- 저장 폴더: {auto_folder}\n"
            f"- 변경 전(before): {base_out_path}\n"
            f"- 변경 후(after): {head_out_path}"
        )
        QMessageBox.information(self, "완료", msg)
        log_append(self.log_output, "\n✅ 모든 작업 완료")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PRDownloaderGUI()
    window.show()
    sys.exit(app.exec_())
