/**
 * @file sfImageSanitizerUI.js
 * @description UI 생성 및 제어 클래스 파일입니다. (뷰 계층)
 *
 * 이 클래스는 애플리케이션의 모든 DOM 요소 생성 및 조작을 전담합니다.
 * 컨트롤러(sfImageSanitizer.js)로부터 명령을 받아 화면을 그리고, 사용자의 상호작용을 감지합니다.
 *
 * [핵심 아키텍처]
 * - 캡슐화: 복잡한 UI 로직을 내부에 감추고, 외부에는 단순하고 명확한 명령 인터페이스만 제공합니다.
 * - 파일 기반 관리: `fileUINodes` Map을 사용하여 각 파일과 그에 해당하는 DOM 요소들을 1:1로 매핑하여
 *   정확하고 효율적으로 UI를 제어합니다.
 *
 * [네임스페이스]
 * - 모든 생성된 요소의 className에는 'sfImageSanitizer-' 접두사를 사용하여 CSS 충돌을 방지합니다.
 */
class sfImageSanitizerUI {
  /**
   * UI 클래스의 생성자입니다.
   * @param {object} [options={}] - UI 설정을 포함하는 옵션 객체.
   */
  constructor(options = {}) {
    const uiOptions = options.ui || {};

    /**
     * @property {Map<File, object>} fileUINodes
     * @description File 객체를 키로, 해당 파일의 모든 관련 DOM 요소 참조를 담은 객체를 값으로 갖는 Map.
     */
    this.fileUINodes = new Map();

    const mainContainer = document.querySelector(uiOptions.mainContainerId);
    if (!mainContainer)
      throw new Error(
        `메인 컨테이너(${uiOptions.mainContainerId})를 찾을 수 없습니다.`
      );
    if (uiOptions.dropZoneHeight)
      mainContainer.style.height = uiOptions.dropZoneHeight;

    this.resultsContainerEl = document.querySelector(
      uiOptions.resultsContainerId
    );
    if (!this.resultsContainerEl)
      throw new Error(
        `결과 컨테이너(${uiOptions.resultsContainerId})를 찾을 수 없습니다.`
      );

    this._createDropZoneUI(mainContainer);
  }

  /**
   * 기능: 드래그 앤 드롭 영역의 UI를 생성합니다. 애플리케이션 로드 시 한 번만 실행됩니다.
   * @private
   */
  _createDropZoneUI(container) {
    const dropZoneEl = document.createElement("div");
    dropZoneEl.className = "sfImageSanitizer-drop-zone";
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
    const fileInputEl = document.createElement("input");
    fileInputEl.type = "file";
    fileInputEl.className = "sfImageSanitizer-file-input";
    fileInputEl.accept = "image/*";
    fileInputEl.multiple = true;
    dropZoneEl.append(dropZonePromptMessageEl, fileInputEl);
    container.appendChild(dropZoneEl);
    this.dropZoneEl = dropZoneEl;
    this.fileInputEl = fileInputEl;
  }

  /**
   * 기능: 특정 파일을 위한 개별 결과 카드 UI를 동적으로 생성합니다.
   * @param {File} file - 이 UI 노드의 주인이 될 File 객체.
   */
  createResultNode(file) {
    const itemEl = document.createElement("div");
    itemEl.className = "sfImageSanitizer-result-item";
    const thumbnailEl = document.createElement("div");
    thumbnailEl.className = "sfImageSanitizer-result-thumbnail";
    const infoAreaEl = document.createElement("div");
    infoAreaEl.className = "sfImageSanitizer-result-info-area";
    const headerEl = document.createElement("div");
    headerEl.className = "sfImageSanitizer-progress-header";
    const fileNameEl = document.createElement("span");
    fileNameEl.className = "sfImageSanitizer-file-name";
    const fileSizeEl = document.createElement("span");
    fileSizeEl.className = "sfImageSanitizer-file-size";
    const resolutionEl = document.createElement("span");
    resolutionEl.className = "sfImageSanitizer-media-resolution";
    const headerRightGroup = document.createElement("div");
    headerRightGroup.className = "sfImageSanitizer-header-right-group";
    const fileInfoEl = document.createElement("span");
    fileInfoEl.className = "sfImageSanitizer-file-info";
    const downloadBtnEl = document.createElement("button");
    downloadBtnEl.className = "sfImageSanitizer-header-icon-btn download-btn";
    downloadBtnEl.type = "button";
    downloadBtnEl.title = "안전한 파일 다운로드";
    downloadBtnEl.textContent = "download";
    downloadBtnEl.style.display = "none";
    const closeBtnEl = document.createElement("button");
    closeBtnEl.className = "sfImageSanitizer-header-icon-btn close-btn";
    closeBtnEl.type = "button";
    closeBtnEl.title = "결과 닫기";
    closeBtnEl.textContent = "close";
    closeBtnEl.onclick = () => {
      itemEl.remove();
      this.fileUINodes.delete(file);
    };
    const collapseToggleBtnEl = document.createElement("button");
    collapseToggleBtnEl.className =
      "sfImageSanitizer-header-icon-btn sfImageSanitizer-collapse-toggle-btn";
    collapseToggleBtnEl.type = "button";
    collapseToggleBtnEl.title = "상세 정보 보기/숨기기";
    const iconExpand = document.createElement("span");
    iconExpand.className = "sfImageSanitizer-icon-expand material-icons";
    iconExpand.textContent = "expand_more";
    const iconCollapse = document.createElement("span");
    iconCollapse.className = "sfImageSanitizer-icon-collapse material-icons";
    iconCollapse.textContent = "expand_less";
    collapseToggleBtnEl.append(iconExpand, iconCollapse);
    headerRightGroup.append(
      fileInfoEl,
      downloadBtnEl,
      closeBtnEl,
      collapseToggleBtnEl
    );
    headerEl.append(fileNameEl, fileSizeEl, resolutionEl, headerRightGroup);
    const collapsibleContentEl = document.createElement("div");
    collapsibleContentEl.className =
      "sfImageSanitizer-collapsible-content collapsed";
    const progressBarContainerEl = document.createElement("div");
    progressBarContainerEl.className = "sfImageSanitizer-progress-bar";
    const progressBarFillEl = document.createElement("div");
    progressBarFillEl.className = "sfImageSanitizer-progress-bar-fill";
    progressBarContainerEl.appendChild(progressBarFillEl);
    const stepContainerEl = document.createElement("div");
    stepContainerEl.className = "sfImageSanitizer-step-container";
    collapsibleContentEl.append(progressBarContainerEl, stepContainerEl);
    const finalResultMessageEl = document.createElement("div");
    finalResultMessageEl.className = "sfImageSanitizer-final-result-message";
    collapseToggleBtnEl.onclick = () => {
      collapsibleContentEl.classList.toggle("collapsed");
      collapseToggleBtnEl.classList.toggle("expanded");
    };
    infoAreaEl.append(headerEl, collapsibleContentEl, finalResultMessageEl);
    itemEl.append(thumbnailEl, infoAreaEl);
    this.resultsContainerEl.appendChild(itemEl);
    this.fileUINodes.set(file, {
      itemEl,
      thumbnailEl,
      fileNameEl,
      fileSizeEl,
      fileInfoEl,
      progressBarFillEl,
      stepContainerEl,
      collapsibleContentEl,
      collapseToggleBtnEl,
      finalResultMessageEl,
      resolutionEl,
      downloadBtnEl,
    });
  }

  addAnalysisStep(file, stepName) {
    const nodes = this.fileUINodes.get(file);
    if (!nodes) return;
    const stepEl = document.createElement("div");
    stepEl.className = "sfImageSanitizer-analysis-step";
    const nameEl = document.createElement("h4");
    nameEl.className = "sfImageSanitizer-step-name";
    nameEl.textContent = stepName;
    const outputEl = document.createElement("div");
    outputEl.className = "sfImageSanitizer-step-output";
    const logsEl = document.createElement("div");
    logsEl.className = "sfImageSanitizer-step-logs";
    stepEl.append(nameEl, outputEl, logsEl);
    nodes.stepContainerEl.appendChild(stepEl);
    nodes.currentStepNodes = { outputEl, logsEl };
  }

  addLogContent(file, contentElement) {
    const nodes = this.fileUINodes.get(file);
    if (!nodes || !nodes.currentStepNodes) return;
    nodes.currentStepNodes.logsEl.appendChild(contentElement);
  }

  addLogMessage(file, message, type = "info") {
    const logEntryEl = document.createElement("p");
    logEntryEl.className = `sfImageSanitizer-log-${type}`;
    logEntryEl.textContent = `> ${message}`;
    logEntryEl.style.whiteSpace = "pre-wrap";
    this.addLogContent(file, logEntryEl);
  }

  setupProgressViews(file, fileName, fileCountText, fileSizeText) {
    const nodes = this.fileUINodes.get(file);
    if (!nodes) return;
    nodes.fileNameEl.textContent = fileName;
    nodes.fileSizeEl.textContent = fileSizeText;
    nodes.fileInfoEl.textContent = fileCountText;
    nodes.progressBarFillEl.style.width = "0%";
    nodes.stepContainerEl.innerHTML = "";
    nodes.resolutionEl.textContent = "";
    nodes.finalResultMessageEl.style.display = "none";
    nodes.downloadBtnEl.style.display = "none";
    nodes.collapsibleContentEl.classList.remove("collapsed");
    nodes.collapseToggleBtnEl.classList.add("expanded");
  }

  updateProgressBar(file, progress) {
    const nodes = this.fileUINodes.get(file);
    if (nodes) nodes.progressBarFillEl.style.width = `${progress * 100}%`;
  }

  updateHexPreview(file, chunkBytes, magicNumber) {
    const nodes = this.fileUINodes.get(file);
    if (!nodes || !nodes.currentStepNodes) return;
    const outputContainer = nodes.currentStepNodes.outputEl;
    outputContainer.innerHTML = "";
    const displayLength = Math.min(chunkBytes.length, 128);
    if (
      magicNumber &&
      magicNumber.length > 0 &&
      displayLength >= magicNumber.length
    ) {
      let highlightedHex = "";
      for (let i = 0; i < magicNumber.length; i++)
        highlightedHex += `<span style="color:#00ff00; font-weight:bold;">${chunkBytes[
          i
        ]
          .toString(16)
          .padStart(2, "0")
          .toUpperCase()}</span> `;
      for (let i = magicNumber.length; i < displayLength; i++)
        highlightedHex +=
          chunkBytes[i].toString(16).padStart(2, "0").toUpperCase() + " ";
      outputContainer.innerHTML = highlightedHex;
    } else {
      let hexString = "";
      for (let i = 0; i < displayLength; i++)
        hexString +=
          chunkBytes[i].toString(16).padStart(2, "0").toUpperCase() + " ";
      outputContainer.textContent = hexString;
    }
  }

  updateResolution(file, width, height) {
    const nodes = this.fileUINodes.get(file);
    if (nodes)
      nodes.resolutionEl.textContent =
        width && height ? `${width} x ${height}` : "";
  }

  showThumbnail(file) {
    const nodes = this.fileUINodes.get(file);
    if (!nodes) return;
    const img = document.createElement("img");
    img.src = URL.createObjectURL(file);
    img.onload = () => URL.revokeObjectURL(img.src);
    nodes.thumbnailEl.innerHTML = "";
    nodes.thumbnailEl.appendChild(img);
  }

  showFinalResultMessage(file, message, type) {
    const nodes = this.fileUINodes.get(file);
    if (!nodes) return;
    const msgEl = nodes.finalResultMessageEl;
    msgEl.textContent = message;
    msgEl.className = `sfImageSanitizer-final-result-message ${type}`;
    msgEl.style.display = "block";
  }

  showDownloadButton(file, downloadName) {
    const nodes = this.fileUINodes.get(file);
    if (nodes) {
      nodes.downloadBtnEl.onclick = () => {
        const url = URL.createObjectURL(file);
        const a = document.createElement("a");
        a.href = url;
        a.download = downloadName;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      };
      nodes.downloadBtnEl.style.display = "flex";
    }
  }

  setFinalState(file, state) {
    const nodes = this.fileUINodes.get(file);
    if (nodes) nodes.itemEl.classList.add(state);
  }

  clearAllResults() {
    this.resultsContainerEl.innerHTML = "";
    this.fileUINodes.clear();
  }

  setDragOverState(isOver) {
    this.dropZoneEl.classList.toggle("drag-over", isOver);
  }
}
