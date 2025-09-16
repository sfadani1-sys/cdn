// 파일이름: sfImageSanitizer.js

/**
 * @file sfImageSanitizer.js
 * @description 애플리케이션의 핵심 로직 컨트롤러 클래스 파일입니다.
 *
 * [리팩토링]
 * 이 클래스는 이제 여러 파일을 순차적으로 처리하고, 각 파일에 대한 UI 노드(결과 카드)를
 * 개별적으로 제어하는 역할을 합니다. UI 클래스와의 모든 상호작용은 어떤 파일에 대한
 * 작업인지 식별하기 위해 'file' 객체를 키로 사용합니다.
 */
class sfImageSanitizer {
  constructor(ui, options = {}) {
    this.ui = ui;
    const logicOptions = options.logic || {};
    this.logger = new sfImageSanitizerLog(logicOptions);

    // [리팩토링] 로거의 출력 콜백은 이제 각 파일을 처리할 때마다 동적으로 설정됩니다.
    // 초기에는 null로 두거나 기본 콘솔 로거를 설정할 수 있습니다.
    this.logger.setOutput(null);

    this.isAnalyzing = false;
    this.fileQueue = [];
    this.totalFiles = 0;
    this.processedFiles = 0;

    this._attachEventListeners();
  }

  /**
   * [리팩토링] 로거로부터 로그 객체를 받아 특정 파일의 UI에 전달하는 콜백 핸들러입니다.
   * @private
   * @param {File} file - 로그가 발생한 대상 파일.
   * @param {object} logObject - 로거가 생성한 로그 객체.
   */
  _handleLog(file, logObject) {
    this.ui.addLogMessage(file, logObject.message, logObject.level);
  }

  _attachEventListeners() {
    const { dropZoneEl, fileInputEl } = this.ui;
    dropZoneEl.addEventListener(
      "click",
      () => !this.isAnalyzing && fileInputEl.click()
    );
    fileInputEl.addEventListener("change", (e) =>
      this.handleFiles(e.target.files)
    );
    dropZoneEl.addEventListener("dragenter", (e) => this._handleDrag(e, true));
    dropZoneEl.addEventListener("dragover", (e) => this._handleDrag(e));
    dropZoneEl.addEventListener("dragleave", (e) => this._handleDrag(e, false));
    dropZoneEl.addEventListener("drop", (e) => this._handleDrop(e));
  }

  _handleDrag(e, isOver) {
    e.preventDefault();
    e.stopPropagation();
    if (typeof isOver === "boolean" && !this.isAnalyzing) {
      this.ui.setDragOverState(isOver);
    }
  }

  _handleDrop(e) {
    e.preventDefault();
    e.stopPropagation();
    if (this.isAnalyzing) return;
    this.ui.setDragOverState(false);
    this.handleFiles(e.dataTransfer.files);
  }

  handleFiles(files) {
    if (!files || files.length === 0) return;

    // 새로운 파일 세션을 시작하기 전에 이전 결과를 모두 지웁니다.
    if (!this.isAnalyzing) {
      this.reset();
    }

    const newImageFiles = Array.from(files).filter((file) =>
      file.type.startsWith("image/")
    );
    if (newImageFiles.length === 0) return;

    this.fileQueue.push(...newImageFiles);
    this.totalFiles = this.fileQueue.length;

    // 현재 분석 프로세스가 실행 중이 아닐 경우에만 새로 시작합니다.
    if (!this.isAnalyzing) {
      this.processFileQueue();
    }
  }

  /**
   * [핵심 리팩토링]
   * 파일 큐에 있는 모든 파일을 순차적으로 처리하는 메인 비동기 루프입니다.
   */
  async processFileQueue() {
    this.isAnalyzing = true;

    // 큐에 파일이 남아있는 동안 계속해서 루프를 돕니다.
    while (this.fileQueue.length > 0) {
      const currentFile = this.fileQueue.shift(); // 큐에서 다음 파일 가져오기
      this.processedFiles++;

      // 1. [UI] 이 파일을 위한 새로운 결과 카드(UI 노드)를 생성하도록 요청합니다.
      this.ui.createResultNode(currentFile);

      const fileCountText = `파일 ${this.processedFiles} / ${this.totalFiles}`;
      const formattedSize = this._formatFileSize(currentFile.size);
      const rawBytes = `${currentFile.size.toLocaleString("ko-KR")} bytes`;
      const fileSizeText = `${formattedSize} (${rawBytes})`;

      // 2. [UI] 생성된 결과 카드의 초기 상태를 설정합니다.
      this.ui.setupProgressViews(
        currentFile,
        currentFile.name,
        fileCountText,
        fileSizeText
      );

      // 3. [Logger] 로거의 출력을 현재 처리 중인 파일의 UI와 연결합니다.
      this.logger.setOutput(this._handleLog.bind(this, currentFile));

      this.logger.info(`초기화...`);

      try {
        this.logger.info("색상 팔레트 추출 중...");
        const palette = await this.extractPaletteForFile(currentFile);
        this.logger.success("팔레트 추출 완료.");

        // 진행 상황 콜백 정의
        const onProgressCallback = (progress, chunkBytes) => {
          this.ui.updateProgressBar(currentFile, progress);
          this.ui.updateHexPreview(currentFile, chunkBytes, palette);
        };

        // 파일 분석 실행
        this.logger.info("파일 스트림 분석 시작...");
        const result = await sfFileFormatAnalyzer.analyze(
          currentFile,
          onProgressCallback,
          this.logger
        );
        this.ui.updateProgressBar(currentFile, 1.0);

        // 결과 처리
        if (result.isValid) {
          this.logger.success(`형식 감지: ${result.format.toUpperCase()}`);
          this.logger.success("파일이 유효합니다.");
          this.ui.setFinalState(currentFile, "success");
          // 4. [UI] 파일이 유효하므로 섬네일을 표시하도록 요청합니다.
          this.ui.showThumbnail(currentFile);
        } else {
          this.logger.error(result.reason);
          this.ui.setFinalState(currentFile, "error");
        }
      } catch (error) {
        this.logger.error(error.toString());
        this.ui.setFinalState(currentFile, "error");
      }
    }

    // 모든 파일 처리가 완료되면 분석 상태를 해제합니다.
    this.isAnalyzing = false;
  }

  _formatFileSize(bytes) {
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB", "TB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  }

  extractPaletteForFile(file) {
    return new Promise((resolve) => {
      const imageUrl = URL.createObjectURL(file);
      this.extractPalette(imageUrl, (palette) => {
        URL.revokeObjectURL(imageUrl);
        resolve(palette);
      });
    });
  }

  extractPalette(imageUrl, callback) {
    const palette = new Set();
    const img = new Image();
    img.crossOrigin = "Anonymous";
    img.onload = () => {
      const canvas = document.createElement("canvas");
      const ctx = canvas.getContext("2d");
      canvas.width = img.width;
      canvas.height = img.height;
      ctx.drawImage(img, 0, 0);
      const imageData = ctx.getImageData(
        0,
        0,
        canvas.width,
        canvas.height
      ).data;
      for (let i = 0; i < 100; i++) {
        const pixelIndex =
          (Math.floor(Math.random() * canvas.height) * canvas.width +
            Math.floor(Math.random() * canvas.width)) *
          4;
        const [r, g, b] = [
          imageData[pixelIndex],
          imageData[pixelIndex + 1],
          imageData[pixelIndex + 2],
        ];
        palette.add(`rgb(${r}, ${g}, ${b})`);
      }
      let finalPalette = Array.from(palette);
      if (finalPalette.length === 0)
        finalPalette = ["#e0e0e0", "#cccccc", "#b0b0b0"];
      callback(finalPalette);
    };
    img.onerror = () => {
      this.logger.error(
        "이미지 로드 실패. 파일이 손상되었거나 지원하지 않는 형식일 수 있습니다."
      );
      callback(["#e0e0e0", "#cccccc", "#b0b0b0"]);
    };
    img.src = imageUrl;
  }

  /**
   * [리팩토링] 애플리케이션 상태와 UI를 완전히 초기 상태로 되돌립니다.
   * 새로운 파일 세션을 시작할 때 호출됩니다.
   */
  reset() {
    this.isAnalyzing = false;
    this.fileQueue = [];
    this.totalFiles = 0;
    this.processedFiles = 0;
    // UI에게 모든 결과 카드를 지우도록 요청합니다.
    this.ui.clearAllResults();
  }
}
