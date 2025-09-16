// 파일이름: sfImageSanitizerUI.js

/**
 * @file sfImageSanitizerUI.js
 * @description UI 생성 및 제어 클래스 파일입니다.
 *
 * [아키텍처 변경]
 * 이 클래스는 이제 두 개의 주요 영역을 관리합니다:
 * 1. 드래그 앤 드롭을 위한 정적 UI 영역 (`#sfImageSanitizer-container`).
 * 2. 각 파일의 분석 결과를 표시할 동적 UI 영역 (`#sfImageSanitizer-results-container`).
 *
 * 각 파일에 대한 UI 요소(결과 카드)를 동적으로 생성하고, `Map`을 사용하여
 * 파일 객체와 해당 파일의 DOM 요소들을 매핑하여 개별적으로 제어합니다.
 */
class sfImageSanitizerUI {
  constructor(options = {}) {
    const uiOptions = options.ui || {};
    this.typingSpeed = uiOptions.typingSpeed ?? 20;

    /**
     * @property {Map<File, object>} fileUINodes - File 객체를 키로, 해당 파일의 UI DOM 요소 참조 객체를 값으로 갖는 Map.
     *                                           이를 통해 특정 파일의 UI를 정확하게 찾아 업데이트할 수 있습니다.
     */
    this.fileUINodes = new Map();

    const mainContainer = document.querySelector(uiOptions.mainContainerId);
    if (!mainContainer)
      throw new Error(
        `메인 컨테이너(${uiOptions.mainContainerId})를 찾을 수 없습니다.`
      );
    if (uiOptions.dropZoneHeight) {
      mainContainer.style.height = uiOptions.dropZoneHeight;
    }

    this.resultsContainerEl = document.querySelector(
      uiOptions.resultsContainerId
    );
    if (!this.resultsContainerEl)
      throw new Error(
        `결과 컨테이너(${uiOptions.resultsContainerId})를 찾을 수 없습니다.`
      );

    // 정적인 드래그 앤 드롭 UI를 생성합니다.
    this._createDropZoneUI(mainContainer);

    // [리팩토링] 메시지 큐와 타이핑 상태는 이제 개별 노드에서 관리될 수 있으나,
    // 단순화를 위해 중앙 큐를 유지하되, 각 메시지에 대상 파일을 포함시킵니다.
    this.messageQueue = [];
    this.isTyping = false;
  }

  /**
   * 드래그 앤 드롭 영역의 UI를 생성합니다. 이 부분은 초기에 한 번만 실행됩니다.
   * @private
   */
  _createDropZoneUI(container) {
    this.dropZoneEl = document.createElement("div");
    this.dropZoneEl.className = "sfImageSanitizer-drop-zone";

    const dropZonePromptMessageEl = document.createElement("div");
    dropZonePromptMessageEl.className = "sfImageSanitizer-prompt-message";
    const dropZonePromptIconEl = document.createElement("i");
    dropZonePromptIconEl.className = "material-icons";
    dropZonePromptIconEl.textContent = "upload_file";
    const dropZonePromptTextMainEl = document.createElement("p");
    dropZonePromptTextMainEl.textContent =
      "스캔할 이미지 파일을 여기에 드래그 앤 드롭하세요";
    const dropZonePromptTextSubEl = document.createElement("p");
    dropZonePromptTextSubEl.textContent =
      "또는 이 영역을 클릭하여 파일을 선택하세요";
    dropZonePromptMessageEl.append(
      dropZonePromptIconEl,
      dropZonePromptTextMainEl,
      dropZonePromptTextSubEl
    );

    this.fileInputEl = document.createElement("input");
    this.fileInputEl.type = "file";
    this.fileInputEl.className = "sfImageSanitizer-file-input";
    this.fileInputEl.accept = "image/*";
    this.fileInputEl.multiple = true;
    this.fileInputEl.style.display = "none";

    this.dropZoneEl.append(dropZonePromptMessageEl, this.fileInputEl);
    container.appendChild(this.dropZoneEl);
  }

  /**
   * [핵심 신규 메서드]
   * 특정 파일을 위한 개별 결과 카드 UI를 동적으로 생성하고 결과 컨테이너에 추가합니다.
   * @param {File} file - 이 UI 노드의 주인이 될 File 객체.
   */
  createResultNode(file) {
    const itemEl = document.createElement("div");
    itemEl.className = "sfImageSanitizer-result-item";

    const thumbnailEl = document.createElement("div");
    thumbnailEl.className = "result-thumbnail";

    const infoAreaEl = document.createElement("div");
    infoAreaEl.className = "result-info-area";

    // --- 정보 영역 내부 컴포넌트 생성 ---
    const headerEl = document.createElement("div");
    headerEl.className = "sfImageSanitizer-progress-header";
    const fileNameEl = document.createElement("span");
    fileNameEl.className = "file-name";
    const fileInfoEl = document.createElement("span");
    fileInfoEl.className = "file-info";
    headerEl.append(fileNameEl, fileInfoEl);

    const progressBarContainerEl = document.createElement("div");
    progressBarContainerEl.className = "sfImageSanitizer-progress-bar";
    const progressBarFillEl = document.createElement("div");
    progressBarFillEl.className = "sfImageSanitizer-progress-bar-fill";
    progressBarContainerEl.appendChild(progressBarFillEl);

    const contentAreaEl = document.createElement("div");
    contentAreaEl.className = "sfImageSanitizer-content-area";

    const statusLogEl = document.createElement("div");
    statusLogEl.className = "sfImageSanitizer-status-log";
    const currentStatusLineEl = document.createElement("p");
    statusLogEl.appendChild(currentStatusLineEl);

    const hexPreviewEl = document.createElement("div");
    hexPreviewEl.className = "sfImageSanitizer-hex-preview";

    const controlsEl = document.createElement("div");
    controlsEl.className = "sfImageSanitizer-progress-controls";
    const clearButtonEl = document.createElement("button");
    clearButtonEl.textContent = "닫기";
    clearButtonEl.onclick = () => {
      itemEl.remove(); // 이 카드만 DOM에서 제거
      this.fileUINodes.delete(file); // Map에서도 해당 파일 정보 제거
    };
    controlsEl.appendChild(clearButtonEl);
    // --- 생성 완료 ---

    contentAreaEl.append(statusLogEl, hexPreviewEl, controlsEl);
    infoAreaEl.append(headerEl, progressBarContainerEl, contentAreaEl);
    itemEl.append(thumbnailEl, infoAreaEl);

    this.resultsContainerEl.appendChild(itemEl);

    // 생성된 모든 DOM 요소의 참조를 Map에 저장하여 나중에 제어할 수 있도록 합니다.
    this.fileUINodes.set(file, {
      itemEl,
      thumbnailEl,
      fileNameEl,
      fileInfoEl,
      progressBarFillEl,
      currentStatusLineEl,
      hexPreviewEl,
      controlsEl,
    });
  }

  // --- [리팩토링] 모든 UI 업데이트 메서드는 이제 'file' 객체를 첫 번째 인자로 받습니다. ---

  setupProgressViews(file, fileName, fileCountText, fileSizeText) {
    const nodes = this.fileUINodes.get(file);
    if (!nodes) return; // 해당 파일의 UI가 없으면 아무것도 하지 않음

    nodes.fileNameEl.textContent = fileName;
    nodes.fileInfoEl.textContent = `${fileCountText} | ${fileSizeText}`;
    nodes.progressBarFillEl.style.width = "0%";
    nodes.currentStatusLineEl.textContent = "";
    nodes.currentStatusLineEl.className = "";
    nodes.hexPreviewEl.innerHTML = "";
    nodes.controlsEl.style.display = "none";
  }

  addLogMessage(file, message, type = "info") {
    // 메시지 큐에 작업 대상 파일 정보도 함께 저장
    this.messageQueue.push({ file, message, type });
    if (!this.isTyping) {
      this._processMessageQueue();
    }
  }

  _processMessageQueue() {
    if (this.messageQueue.length === 0) {
      this.isTyping = false;
      return;
    }
    this.isTyping = true;
    const { file, message, type } = this.messageQueue.shift();

    const nodes = this.fileUINodes.get(file);
    if (!nodes) {
      // 노드가 이미 닫혔을 수 있으므로 다음 큐 처리
      this._processMessageQueue();
      return;
    }

    const statusLineEl = nodes.currentStatusLineEl;
    statusLineEl.className = `log-${type}`;
    statusLineEl.textContent = "> ";

    let charIndex = 0;
    const typingInterval = setInterval(() => {
      if (charIndex === message.length) {
        clearInterval(typingInterval);
        this._processMessageQueue();
        return;
      }
      statusLineEl.textContent += message[charIndex];
      charIndex++;
    }, this.typingSpeed);
  }

  updateProgressBar(file, progress) {
    const nodes = this.fileUINodes.get(file);
    if (nodes) nodes.progressBarFillEl.style.width = `${progress * 100}%`;
  }

  updateHexPreview(file, chunkBytes, palette) {
    const nodes = this.fileUINodes.get(file);
    if (!nodes) return;
    let hexString = "";
    const displayLength = Math.min(chunkBytes.length, 128);
    for (let i = 0; i < displayLength; i++) {
      const hexByte = chunkBytes[i].toString(16).padStart(2, "0");
      const randomColor = palette[Math.floor(Math.random() * palette.length)];
      hexString += `<span style="color:${randomColor}">${hexByte}</span> `;
    }
    nodes.hexPreviewEl.innerHTML = hexString;
  }

  /**
   * [신규 메서드] 검증이 완료된 파일의 섬네일을 생성하여 표시합니다.
   * @param {File} file - 섬네일을 표시할 대상 파일.
   */
  showThumbnail(file) {
    const nodes = this.fileUINodes.get(file);
    if (!nodes) return;

    const img = document.createElement("img");
    // File 객체로부터 임시 URL을 생성하여 이미지 소스로 사용
    img.src = URL.createObjectURL(file);
    // 메모리 누수 방지를 위해, 이미지 로드가 끝나면 URL을 해제합니다.
    img.onload = () => URL.revokeObjectURL(img.src);

    nodes.thumbnailEl.innerHTML = ""; // 기존 내용(있다면) 지우기
    nodes.thumbnailEl.appendChild(img);
  }

  setFinalState(file, state) {
    const nodes = this.fileUINodes.get(file);
    if (!nodes) return;
    nodes.itemEl.classList.add(state);
    nodes.controlsEl.style.display = "flex"; // '닫기' 버튼 표시
  }

  /**
   * [신규 메서드] 모든 결과 카드를 지웁니다.
   */
  clearAllResults() {
    this.resultsContainerEl.innerHTML = "";
    this.fileUINodes.clear();
  }

  // 드롭존 상태를 제어하는 메서드들은 그대로 유지됩니다.
  setDragOverState(isOver) {
    this.dropZoneEl.classList.toggle("drag-over", isOver);
  }
}
